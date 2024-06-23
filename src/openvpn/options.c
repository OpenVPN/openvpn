/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2008-2024 David Sommerseth <dazo@eurephia.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * 2004-01-28: Added Socks5 proxy support
 *   (Christof Meerwald, http://cmeerw.org)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef HAVE_CONFIG_VERSION_H
#include "config-version.h"
#endif

#include "syshead.h"

#include "buffer.h"
#include "error.h"
#include "common.h"
#include "run_command.h"
#include "shaper.h"
#include "crypto.h"
#include "ssl.h"
#include "ssl_ncp.h"
#include "options.h"
#include "misc.h"
#include "socket.h"
#include "packet_id.h"
#include "pkcs11.h"
#include "win32.h"
#include "push.h"
#include "pool.h"
#include "proto.h"
#include "helper.h"
#include "manage.h"
#include "forward.h"
#include "ssl_verify.h"
#include "platform.h"
#include "xkey_common.h"
#include "dco.h"
#include <ctype.h>

#include "memdbg.h"

const char title_string[] =
    PACKAGE_STRING
#ifdef CONFIGURE_GIT_REVISION
    " [git:" CONFIGURE_GIT_REVISION CONFIGURE_GIT_FLAGS "]"
#endif
    " " TARGET_ALIAS
#if defined(ENABLE_CRYPTO_MBEDTLS)
    " [SSL (mbed TLS)]"
#elif defined(ENABLE_CRYPTO_OPENSSL)
    " [SSL (OpenSSL)]"
#else
    " [SSL]"
#endif /* defined(ENABLE_CRYPTO_MBEDTLS) */
#ifdef USE_COMP
#ifdef ENABLE_LZO
    " [LZO]"
#endif
#ifdef ENABLE_LZ4
    " [LZ4]"
#endif
#ifdef ENABLE_COMP_STUB
    " [COMP_STUB]"
#endif
#endif /* USE_COMP */
#if EPOLL
    " [EPOLL]"
#endif
#ifdef PRODUCT_TAP_DEBUG
    " [TAPDBG]"
#endif
#ifdef ENABLE_PKCS11
    " [PKCS11]"
#endif
#if ENABLE_IP_PKTINFO
#if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST)
    " [MH/PKTINFO]"
#elif defined(IP_RECVDSTADDR)
    " [MH/RECVDA]"
#endif
#endif
    " [AEAD]"
#ifdef ENABLE_DCO
    " [DCO]"
#endif
#ifdef CONFIGURE_GIT_REVISION
    " built on " __DATE__
#endif
;

#ifndef ENABLE_SMALL

static const char usage_message[] =
    "%s\n"
    "\n"
    "General Options:\n"
    "--config file   : Read configuration options from file.\n"
    "--help          : Show options.\n"
    "--version       : Show copyright and version information.\n"
    "\n"
    "Tunnel Options:\n"
    "--local host    : Local host name or ip address. Implies --bind.\n"
    "--remote host [port] : Remote host name or ip address.\n"
    "--remote-random : If multiple --remote options specified, choose one randomly.\n"
    "--remote-random-hostname : Add a random string to remote DNS name.\n"
    "--mode m        : Major mode, m = 'p2p' (default, point-to-point) or 'server'.\n"
    "--proto p       : Use protocol p for communicating with peer.\n"
    "                  p = udp (default), tcp-server, tcp-client\n"
    "                      udp4, tcp4-server, tcp4-client\n"
    "                      udp6, tcp6-server, tcp6-client\n"
    "--proto-force p : only consider protocol p in list of connection profiles.\n"
    "                  p = udp or tcp\n"
    "--connect-retry n [m] : For client, number of seconds to wait between\n"
    "                  connection retries (default=%d). On repeated retries\n"
    "                  the wait time is exponentially increased to a maximum of m\n"
    "                  (default=%d).\n"
    "--connect-retry-max n : Maximum connection attempt retries, default infinite.\n"
    "--http-proxy s p [up] [auth] : Connect to remote host\n"
    "                  through an HTTP proxy at address s and port p.\n"
    "                  If proxy authentication is required,\n"
    "                  up is a file containing username/password on 2 lines, or\n"
    "                  'stdin' to prompt from console.  Add auth='ntlm' if\n"
    "                  the proxy requires NTLM authentication.\n"
    "--http-proxy s p 'auto[-nct]' : Like the above directive, but automatically\n"
    "                  determine auth method and query for username/password\n"
    "                  if needed.  auto-nct disables weak proxy auth methods.\n"
    "--http-proxy-option type [parm] : Set extended HTTP proxy options.\n"
    "                                  Repeat to set multiple options.\n"
    "                  VERSION version (default=1.0)\n"
    "                  AGENT user-agent\n"
    "--socks-proxy s [p] [up] : Connect to remote host through a Socks5 proxy at\n"
    "                  address s and port p (default port = 1080).\n"
    "                  If proxy authentication is required,\n"
    "                  up is a file containing username/password on 2 lines, or\n"
    "                  'stdin' to prompt for console.\n"
    "--socks-proxy-retry : Retry indefinitely on Socks proxy errors.\n"
    "--resolv-retry n: If hostname resolve fails for --remote, retry\n"
    "                  resolve for n seconds before failing (disabled by default).\n"
    "                  Set n=\"infinite\" to retry indefinitely.\n"
    "--float         : Allow remote to change its IP address/port, such as through\n"
    "                  DHCP (this is the default if --remote is not used).\n"
    "--ipchange cmd  : Run command cmd on remote ip address initial\n"
    "                  setting or change -- execute as: cmd ip-address port#\n"
    "--port port     : TCP/UDP port # for both local and remote.\n"
    "--lport port    : TCP/UDP port # for local (default=%s). Implies --bind.\n"
    "--rport port    : TCP/UDP port # for remote (default=%s).\n"
    "--bind          : Bind to local address and port. (This is the default unless\n"
    "                  --proto tcp-client"
    " or --http-proxy"
    " or --socks-proxy"
    " is used).\n"
    "--nobind        : Do not bind to local address and port.\n"
    "--dev tunX|tapX : tun/tap device (X can be omitted for dynamic device.\n"
    "--dev-type dt   : Which device type are we using? (dt = tun or tap) Use\n"
    "                  this option only if the tun/tap device used with --dev\n"
    "                  does not begin with \"tun\" or \"tap\".\n"
    "--dev-node node : Explicitly set the device node rather than using\n"
    "                  /dev/net/tun, /dev/tun, /dev/tap, etc.\n"
#if defined(ENABLE_DCO)
    "--disable-dco   : Do not attempt using Data Channel Offload.\n"
#endif
    "--lladdr hw     : Set the link layer address of the tap device.\n"
    "--topology t    : Set --dev tun topology: 'net30', 'p2p', or 'subnet'.\n"
#ifdef ENABLE_IPROUTE
    "--iproute cmd   : Use this command instead of default " IPROUTE_PATH ".\n"
#endif
    "--ifconfig l rn : TUN: configure device to use IP address l as a local\n"
    "                  endpoint and rn as a remote endpoint.  l & rn should be\n"
    "                  swapped on the other peer.  l & rn must be private\n"
    "                  addresses outside of the subnets used by either peer.\n"
    "                  TAP: configure device to use IP address l as a local\n"
    "                  endpoint and rn as a subnet mask.\n"
    "--ifconfig-ipv6 l r : configure device to use IPv6 address l as local\n"
    "                      endpoint (as a /64) and r as remote endpoint\n"
    "--ifconfig-noexec : Don't actually execute ifconfig/netsh command, instead\n"
    "                    pass --ifconfig parms by environment to scripts.\n"
    "--ifconfig-nowarn : Don't warn if the --ifconfig option on this side of the\n"
    "                    connection doesn't match the remote side.\n"
    "--route network [netmask] [gateway] [metric] :\n"
    "                  Add route to routing table after connection\n"
    "                  is established.  Multiple routes can be specified.\n"
    "                  netmask default: 255.255.255.255\n"
    "                  gateway default: taken from --route-gateway or --ifconfig\n"
    "                  Specify default by leaving blank or setting to \"default\".\n"
    "--route-ipv6 network/bits [gateway] [metric] :\n"
    "                  Add IPv6 route to routing table after connection\n"
    "                  is established.  Multiple routes can be specified.\n"
    "                  gateway default: taken from --route-ipv6-gateway or 'remote'\n"
    "                  in --ifconfig-ipv6\n"
    "--route-gateway gw|'dhcp' : Specify a default gateway for use with --route.\n"
    "--route-ipv6-gateway gw : Specify a default gateway for use with --route-ipv6.\n"
    "--route-metric m : Specify a default metric for use with --route.\n"
    "--route-delay n [w] : Delay n seconds after connection initiation before\n"
    "                  adding routes (may be 0).  If not specified, routes will\n"
    "                  be added immediately after tun/tap open.  On Windows, wait\n"
    "                  up to w seconds for TUN/TAP adapter to come up.\n"
    "--route-up cmd  : Run command cmd after routes are added.\n"
    "--route-pre-down cmd : Run command cmd before routes are removed.\n"
    "--route-noexec  : Don't add routes automatically.  Instead pass routes to\n"
    "                  --route-up script using environmental variables.\n"
    "--route-nopull  : When used with --client or --pull, accept options pushed\n"
    "                  by server EXCEPT for routes, dns, and dhcp options.\n"
    "--allow-pull-fqdn : Allow client to pull DNS names from server for\n"
    "                    --ifconfig, --route, and --route-gateway.\n"
    "--redirect-gateway [flags]: Automatically execute routing\n"
    "                  commands to redirect all outgoing IP traffic through the\n"
    "                  VPN.  Add 'local' flag if both " PACKAGE_NAME " servers are directly\n"
    "                  connected via a common subnet, such as with WiFi.\n"
    "                  Add 'def1' flag to set default route using using 0.0.0.0/1\n"
    "                  and 128.0.0.0/1 rather than 0.0.0.0/0.  Add 'bypass-dhcp'\n"
    "                  flag to add a direct route to DHCP server, bypassing tunnel.\n"
    "                  Add 'bypass-dns' flag to similarly bypass tunnel for DNS.\n"
    "--redirect-private [flags]: Like --redirect-gateway, but omit actually changing\n"
    "                  the default gateway.  Useful when pushing private subnets.\n"
    "--block-ipv6     : (Client) Instead sending IPv6 to the server generate\n"
    "                   ICMPv6 host unreachable messages on the client.\n"
    "                   (Server) Instead of forwarding IPv6 packets send\n"
    "                   ICMPv6 host unreachable packets to the client.\n"
    "--client-nat snat|dnat network netmask alias : on client add 1-to-1 NAT rule.\n"
    "--push-peer-info : (client only) push client info to server.\n"
    "--setenv name value : Set a custom environmental variable to pass to script.\n"
    "--setenv FORWARD_COMPATIBLE 1 : Relax config file syntax checking to allow\n"
    "                  directives for future OpenVPN versions to be ignored.\n"
    "--ignore-unknown-option opt1 opt2 ...: Relax config file syntax. Allow\n"
    "                  these options to be ignored when unknown\n"
    "--script-security level: Where level can be:\n"
    "                  0 -- strictly no calling of external programs\n"
    "                  1 -- (default) only call built-ins such as ifconfig\n"
    "                  2 -- allow calling of built-ins and scripts\n"
    "                  3 -- allow password to be passed to scripts via env\n"
    "--shaper n      : Restrict output to peer to n bytes per second.\n"
    "--keepalive n m : Helper option for setting timeouts in server mode.  Send\n"
    "                  ping once every n seconds, restart if ping not received\n"
    "                  for m seconds.\n"
    "--inactive n [bytes] : Exit after n seconds of activity on tun/tap device\n"
    "                  produces a combined in/out byte count < bytes.\n"
    "--session-timeout n: Limit connection time to n seconds.\n"
    "--ping-exit n   : Exit if n seconds pass without reception of remote ping.\n"
    "--ping-restart n: Restart if n seconds pass without reception of remote ping.\n"
    "--ping-timer-rem: Run the --ping-exit/--ping-restart timer only if we have a\n"
    "                  remote address.\n"
    "--ping n        : Ping remote once every n seconds over TCP/UDP port.\n"
#if ENABLE_IP_PKTINFO
    "--multihome     : Configure a multi-homed UDP server.\n"
#endif
    "--fast-io       : Optimize TUN/TAP/UDP writes.\n"
    "--remap-usr1 s  : On SIGUSR1 signals, remap signal (s='SIGHUP' or 'SIGTERM').\n"
    "--persist-tun   : Keep tun/tap device open across SIGUSR1 or --ping-restart.\n"
    "--persist-remote-ip : Keep remote IP address across SIGUSR1 or --ping-restart.\n"
    "--persist-local-ip  : Keep local IP address across SIGUSR1 or --ping-restart.\n"
    "--persist-key   : Don't re-read key files across SIGUSR1 or --ping-restart.\n"
#if PASSTOS_CAPABILITY
    "--passtos       : TOS passthrough (applies to IPv4 only).\n"
#endif
    "--tun-mtu n     : Take the tun/tap device MTU to be n and derive the\n"
    "                  TCP/UDP MTU from it (default=%d).\n"
    "--tun-mtu-extra n : Assume that tun/tap device might return as many\n"
    "                  as n bytes more than the tun-mtu size on read\n"
    "                  (default TUN=0 TAP=%d).\n"
    "--link-mtu n    : Take the TCP/UDP device MTU to be n and derive the tun MTU\n"
    "                  from it.\n"
    "--mtu-disc type : Should we do Path MTU discovery on TCP/UDP channel?\n"
    "                  'no'    -- Never send DF (Don't Fragment) frames\n"
    "                  'maybe' -- Use per-route hints\n"
    "                  'yes'   -- Always DF (Don't Fragment)\n"
    "--mtu-test      : Empirically measure and report MTU.\n"
#ifdef ENABLE_FRAGMENT
    "--fragment max  : Enable internal datagram fragmentation so that no UDP\n"
    "                  datagrams are sent which are larger than max bytes.\n"
    "                  Adds 4 bytes of overhead per datagram.\n"
#endif
    "--mssfix [n]    : Set upper bound on TCP MSS, default = tun-mtu size\n"
    "                  or --fragment max value, whichever is lower.\n"
    "--sndbuf size   : Set the TCP/UDP send buffer size.\n"
    "--rcvbuf size   : Set the TCP/UDP receive buffer size.\n"
#if defined(TARGET_LINUX) && HAVE_DECL_SO_MARK
    "--mark value    : Mark encrypted packets being sent with value. The mark value\n"
    "                  can be matched in policy routing and packetfilter rules.\n"
    "--bind-dev dev  : Bind to the given device when making connection to a peer or\n"
    "                  listening for connections. This allows sending encrypted packets\n"
    "                  via a VRF present on the system.\n"
#endif
    "--txqueuelen n  : Set the tun/tap TX queue length to n (Linux only).\n"
#ifdef ENABLE_MEMSTATS
    "--memstats file : Write live usage stats to memory mapped binary file.\n"
#endif
    "--mlock         : Disable Paging -- ensures key material and tunnel\n"
    "                  data will never be written to disk.\n"
    "--up cmd        : Run command cmd after successful tun device open.\n"
    "                  Execute as: cmd tun/tap-dev tun-mtu link-mtu \\\n"
    "                              ifconfig-local-ip ifconfig-remote-ip\n"
    "                  (pre --user or --group UID/GID change)\n"
    "--up-delay      : Delay tun/tap open and possible --up script execution\n"
    "                  until after TCP/UDP connection establishment with peer.\n"
    "--down cmd      : Run command cmd after tun device close.\n"
    "                  (post --user/--group UID/GID change and/or --chroot)\n"
    "                  (command parameters are same as --up option)\n"
    "--down-pre      : Run --down command before TUN/TAP close.\n"
    "--up-restart    : Run up/down commands for all restarts including those\n"
    "                  caused by --ping-restart or SIGUSR1\n"
    "--user user     : Set UID to user after initialization.\n"
    "--group group   : Set GID to group after initialization.\n"
    "--chroot dir    : Chroot to this directory after initialization.\n"
#ifdef ENABLE_SELINUX
    "--setcon context: Apply this SELinux context after initialization.\n"
#endif
    "--cd dir        : Change to this directory before initialization.\n"
    "--daemon [name] : Become a daemon after initialization.\n"
    "                  The optional 'name' parameter will be passed\n"
    "                  as the program name to the system logger.\n"
    "--syslog [name] : Output to syslog, but do not become a daemon.\n"
    "                  See --daemon above for a description of the 'name' parm.\n"
    "--log file      : Output log to file which is created/truncated on open.\n"
    "--log-append file : Append log to file, or create file if nonexistent.\n"
    "--suppress-timestamps : Don't log timestamps to stdout/stderr.\n"
    "--machine-readable-output : Always log timestamp, message flags to stdout/stderr.\n"
    "--writepid file : Write main process ID to file.\n"
    "--nice n        : Change process priority (>0 = lower, <0 = higher).\n"
    "--echo [parms ...] : Echo parameters to log output.\n"
    "--verb n        : Set output verbosity to n (default=%d):\n"
    "                  (Level 3 is recommended if you want a good summary\n"
    "                  of what's happening without being swamped by output).\n"
    "                : 0 -- no output except fatal errors\n"
    "                : 1 -- startup info + connection initiated messages +\n"
    "                       non-fatal encryption & net errors\n"
    "                : 2,3 -- show TLS negotiations & route info\n"
    "                : 4 -- show parameters\n"
    "                : 5 -- show 'RrWw' chars on console for each packet sent\n"
    "                       and received from TCP/UDP (caps) or tun/tap (lc)\n"
    "                : 6 to 11 -- debug messages of increasing verbosity\n"
    "--mute n        : Log at most n consecutive messages in the same category.\n"
    "--status file [n] : Write operational status to file every n seconds.\n"
    "--status-version [n] : Choose the status file format version number.\n"
    "                  Currently, n can be 1, 2, or 3 (default=1).\n"
    "--disable-occ   : (DEPRECATED) Disable options consistency check between peers.\n"
#ifdef ENABLE_DEBUG
    "--gremlin mask  : Special stress testing mode (for debugging only).\n"
#endif
#if defined(USE_COMP)
    "--compress alg  : Use compression algorithm alg\n"
    "--allow-compression: Specify whether compression should be allowed\n"
#if defined(ENABLE_LZO)
    "--comp-lzo      : Use LZO compression -- may add up to 1 byte per\n"
    "                  packet for incompressible data.\n"
    "--comp-noadapt  : Don't use adaptive compression when --comp-lzo\n"
    "                  is specified.\n"
#endif
#endif
#ifdef ENABLE_MANAGEMENT
    "--management ip port [pass] : Enable a TCP server on ip:port to handle\n"
    "                  management functions.  pass is a password file\n"
    "                  or 'stdin' to prompt from console.\n"
#if UNIX_SOCK_SUPPORT
    "                  To listen on a unix domain socket, specific the pathname\n"
    "                  in place of ip and use 'unix' as the port number.\n"
#endif
    "--management-client : Management interface will connect as a TCP client to\n"
    "                      ip/port rather than listen as a TCP server.\n"
    "--management-query-passwords : Query management channel for private key\n"
    "                  and auth-user-pass passwords.\n"
    "--management-query-proxy : Query management channel for proxy information.\n"
    "--management-query-remote : Query management channel for --remote directive.\n"
    "--management-hold : Start " PACKAGE_NAME " in a hibernating state, until a client\n"
    "                    of the management interface explicitly starts it.\n"
    "--management-signal : Issue SIGUSR1 when management disconnect event occurs.\n"
    "--management-forget-disconnect : Forget passwords when management disconnect\n"
    "                                 event occurs.\n"
    "--management-up-down : Report tunnel up/down events to management interface.\n"
    "--management-log-cache n : Cache n lines of log file history for usage\n"
    "                  by the management channel.\n"
#if UNIX_SOCK_SUPPORT
    "--management-client-user u  : When management interface is a unix socket, only\n"
    "                              allow connections from user u.\n"
    "--management-client-group g : When management interface is a unix socket, only\n"
    "                              allow connections from group g.\n"
#endif
    "--management-client-auth : gives management interface client the responsibility\n"
    "                           to authenticate clients after their client certificate\n"
    "			      has been verified.\n"
#endif /* ifdef ENABLE_MANAGEMENT */
#ifdef ENABLE_PLUGIN
    "--plugin m [str]: Load plug-in module m passing str as an argument\n"
    "                  to its initialization function.\n"
#endif
    "--vlan-tagging  : Enable 802.1Q-based VLAN tagging.\n"
    "--vlan-accept tagged|untagged|all : Set VLAN tagging mode. Default is 'all'.\n"
    "--vlan-pvid v   : Sets the Port VLAN Identifier. Defaults to 1.\n"
    "\n"
    "Multi-Client Server options (when --mode server is used):\n"
    "--server network netmask : Helper option to easily configure server mode.\n"
    "--server-ipv6 network/bits : Configure IPv6 server mode.\n"
    "--server-bridge [IP netmask pool-start-IP pool-end-IP] : Helper option to\n"
    "                    easily configure ethernet bridging server mode.\n"
    "--push \"option\" : Push a config file option back to the peer for remote\n"
    "                  execution.  Peer must specify --pull in its config file.\n"
    "--push-reset    : Don't inherit global push list for specific\n"
    "                  client instance.\n"
    "--push-remove opt : Remove options matching 'opt' from the push list for\n"
    "                  a specific client instance.\n"
    "--ifconfig-pool start-IP end-IP [netmask] : Set aside a pool of subnets\n"
    "                  to be dynamically allocated to connecting clients.\n"
    "--ifconfig-pool-persist file [seconds] : Persist/unpersist ifconfig-pool\n"
    "                  data to file, at seconds intervals (default=600).\n"
    "                  If seconds=0, file will be treated as read-only.\n"
    "--ifconfig-ipv6-pool base-IP/bits : set aside an IPv6 network block\n"
    "                  to be dynamically allocated to connecting clients.\n"
    "--ifconfig-push local remote-netmask : Push an ifconfig option to remote,\n"
    "                  overrides --ifconfig-pool dynamic allocation.\n"
    "                  Only valid in a client-specific config file.\n"
    "--ifconfig-ipv6-push local/bits remote : Push an ifconfig-ipv6 option to\n"
    "                  remote, overrides --ifconfig-ipv6-pool allocation.\n"
    "                  Only valid in a client-specific config file.\n"
    "--iroute network [netmask] : Route subnet to client.\n"
    "--iroute-ipv6 network/bits : Route IPv6 subnet to client.\n"
    "                  Sets up internal routes only.\n"
    "                  Only valid in a client-specific config file.\n"
    "--disable       : Client is disabled.\n"
    "                  Only valid in a client-specific config file.\n"
    "--verify-client-cert [none|optional|require] : perform no, optional or\n"
    "                  mandatory client certificate verification.\n"
    "                  Default is to require the client to supply a certificate.\n"
    "--username-as-common-name  : For auth-user-pass authentication, use\n"
    "                  the authenticated username as the common name,\n"
    "                  rather than the common name from the client cert.\n"
    "--auth-user-pass-verify cmd method: Query client for username/password and\n"
    "                  run command cmd to verify.  If method='via-env', pass\n"
    "                  user/pass via environment, if method='via-file', pass\n"
    "                  user/pass via temporary file.\n"
    "--auth-gen-token  [lifetime] Generate a random authentication token which is pushed\n"
    "                  to each client, replacing the password.  Useful when\n"
    "                  OTP based two-factor auth mechanisms are in use and\n"
    "                  --reneg-* options are enabled. Optionally a lifetime in seconds\n"
    "                  for generated tokens can be set.\n"
    "--opt-verify    : (DEPRECATED) Clients that connect with options that are incompatible\n"
    "                  with those of the server will be disconnected.\n"
    "--auth-user-pass-optional : Allow connections by clients that don't\n"
    "                  specify a username/password.\n"
    "--no-name-remapping : (DEPRECATED) Allow Common Name and X509 Subject to include\n"
    "                      any printable character.\n"
    "--client-to-client : Internally route client-to-client traffic.\n"
    "--duplicate-cn  : Allow multiple clients with the same common name to\n"
    "                  concurrently connect.\n"
    "--client-connect cmd : Run command cmd on client connection.\n"
    "--client-disconnect cmd : Run command cmd on client disconnection.\n"
    "--client-config-dir dir : Directory for custom client config files.\n"
    "--ccd-exclusive : Refuse connection unless custom client config is found.\n"
    "--tmp-dir dir   : Temporary directory, used for --client-connect return file and plugin communication.\n"
    "--hash-size r v : Set the size of the real address hash table to r and the\n"
    "                  virtual address table to v.\n"
    "--bcast-buffers n : Allocate n broadcast buffers.\n"
    "--tcp-queue-limit n : Maximum number of queued TCP output packets.\n"
    "--tcp-nodelay   : Macro that sets TCP_NODELAY socket flag on the server\n"
    "                  as well as pushes it to connecting clients.\n"
    "--learn-address cmd : Run command cmd to validate client virtual addresses.\n"
    "--connect-freq n s : Allow a maximum of n new connections per s seconds.\n"
    "--connect-freq-initial n s : Allow a maximum of n replies for initial connections attempts per s seconds.\n"
    "--max-clients n : Allow a maximum of n simultaneously connected clients.\n"
    "--max-routes-per-client n : Allow a maximum of n internal routes per client.\n"
    "--stale-routes-check n [t] : Remove routes with a last activity timestamp\n"
    "                             older than n seconds. Run this check every t\n"
    "                             seconds (defaults to n).\n"
    "--explicit-exit-notify [n] : In UDP server mode send [RESTART] command on exit/restart to connected\n"
    "                             clients. n = 1 - reconnect to same server,\n"
    "                             2 - advance to next server, default=1.\n"
#if PORT_SHARE
    "--port-share host port [dir] : When run in TCP mode, proxy incoming HTTPS\n"
    "                  sessions to a web server at host:port.  dir specifies an\n"
    "                  optional directory to write origin IP:port data.\n"
#endif
    "\n"
    "Client options (when connecting to a multi-client server):\n"
    "--client         : Helper option to easily configure client mode.\n"
    "--auth-user-pass [up] : Authenticate with server using username/password.\n"
    "                  up is a file containing the username on the first line,\n"
    "                  and a password on the second. If either the password or both\n"
    "                  the username and the password are omitted OpenVPN will prompt\n"
    "                  for them from console.\n"
    "--pull           : Accept certain config file options from the peer as if they\n"
    "                  were part of the local config file.  Must be specified\n"
    "                  when connecting to a '--mode server' remote host.\n"
    "--pull-filter accept|ignore|reject t : Filter each option received from the\n"
    "                  server if it starts with the text t. The action flag accept,\n"
    "                  ignore or reject causes the option to be allowed, removed or\n"
    "                  rejected with error. May be specified multiple times, and\n"
    "                  each filter is applied in the order of appearance.\n"
    "--dns server <n> <option> <value> [value ...] : Configure option for DNS server #n\n"
    "                  Valid options are :\n"
    "                  address <addr[:port]> [addr[:port] ...] : server addresses 4/6\n"
    "                  resolve-domains <domain> [domain ...] : split domains\n"
    "                  dnssec <yes|no|optional> : option to use DNSSEC\n"
    "                  type <DoH|DoT> : query server over HTTPS / TLS\n"
    "                  sni <domain> : DNS server name indication\n"
    "--dns search-domains <domain> [domain ...]:\n"
    "                  Add domains to DNS domain search list\n"
    "--auth-retry t  : How to handle auth failures.  Set t to\n"
    "                  none (default), interact, or nointeract.\n"
    "--static-challenge t e : Enable static challenge/response protocol using\n"
    "                  challenge text t, with e indicating echo flag (0|1)\n"
    "--connect-timeout n : when polling possible remote servers to connect to\n"
    "                  in a round-robin fashion, spend no more than n seconds\n"
    "                  waiting for a response before trying the next server.\n"
    "--allow-recursive-routing : When this option is set, OpenVPN will not drop\n"
    "                  incoming tun packets with same destination as host.\n"
    "--explicit-exit-notify [n] : On exit/restart, send exit signal to\n"
    "                  server/remote. n = # of retries, default=1.\n"
    "\n"
    "Data Channel Encryption Options (must be compatible between peers):\n"
    "(These options are meaningful for both Static Key & TLS-mode)\n"
    "--secret f [d]  : (DEPRECATED) Enable Static Key encryption mode (non-TLS).\n"
    "                  Use shared secret file f, generate with --genkey.\n"
    "                  The optional d parameter controls key directionality.\n"
    "                  If d is specified, use separate keys for each\n"
    "                  direction, set d=0 on one side of the connection,\n"
    "                  and d=1 on the other side.\n"
    "--auth alg      : Authenticate packets with HMAC using message\n"
    "                  digest algorithm alg (default=%s).\n"
    "                  (usually adds 16 or 20 bytes per packet)\n"
    "                  Set alg=none to disable authentication.\n"
    "--cipher alg    : Encrypt packets with cipher algorithm alg.\n"
    "                  You should usually use --data-ciphers instead.\n"
    "                  Set alg=none to disable encryption.\n"
    "--data-ciphers list : List of ciphers that are allowed to be negotiated.\n"
#ifndef ENABLE_CRYPTO_MBEDTLS
    "--engine [name] : Enable OpenSSL hardware crypto engine functionality.\n"
#endif
    "--no-replay     : (DEPRECATED) Disable replay protection.\n"
    "--mute-replay-warnings : Silence the output of replay warnings to log file.\n"
    "--replay-window n [t]  : Use a replay protection sliding window of size n\n"
    "                         and a time window of t seconds.\n"
    "                         Default n=%d t=%d\n"
    "--replay-persist file : Persist replay-protection state across sessions\n"
    "                  using file.\n"
    "--test-crypto   : Run a self-test of crypto features enabled.\n"
    "                  For debugging only.\n"
#ifdef ENABLE_PREDICTION_RESISTANCE
    "--use-prediction-resistance: Enable prediction resistance on the random\n"
    "                             number generator.\n"
#endif
    "\n"
    "TLS Key Negotiation Options:\n"
    "(These options are meaningful only for TLS-mode)\n"
    "--tls-server    : Enable TLS and assume server role during TLS handshake.\n"
    "--tls-client    : Enable TLS and assume client role during TLS handshake.\n"
    "--ca file       : Certificate authority file in .pem format containing\n"
    "                  root certificate.\n"
#ifndef ENABLE_CRYPTO_MBEDTLS
    "--capath dir    : A directory of trusted certificates (CAs"
    " and CRLs).\n"
#endif /* ENABLE_CRYPTO_MBEDTLS */
    "--dh file       : File containing Diffie Hellman parameters\n"
    "                  in .pem format (for --tls-server only).\n"
    "                  Use \"openssl dhparam -out dh1024.pem 1024\" to generate.\n"
    "--cert file     : Local certificate in .pem format -- must be signed\n"
    "                  by a Certificate Authority in --ca file.\n"
    "--extra-certs file : one or more PEM certs that complete the cert chain.\n"
    "--key file      : Local private key in .pem format.\n"
    "--tls-version-min <version> ['or-highest'] : sets the minimum TLS version we\n"
    "    will accept from the peer.  If version is unrecognized and 'or-highest'\n"
    "    is specified, require max TLS version supported by SSL implementation.\n"
    "--tls-version-max <version> : sets the maximum TLS version we will use.\n"
#ifndef ENABLE_CRYPTO_MBEDTLS
    "--pkcs12 file   : PKCS#12 file containing local private key, local certificate\n"
    "                  and optionally the root CA certificate.\n"
#endif
#ifdef ENABLE_X509ALTUSERNAME
    "--x509-username-field : Field in x509 certificate containing the username.\n"
    "                        Default is CN in the Subject field.\n"
#endif
    "--verify-hash hash [algo] : Specify fingerprint for level-1 certificate.\n"
    "                            Valid algo flags are SHA1 and SHA256. \n"
#ifdef _WIN32
    "--cryptoapicert select-string : Load the certificate and private key from the\n"
    "                  Windows Certificate System Store.\n"
#endif
    "--tls-cipher l  : A list l of allowable TLS ciphers separated by : (optional).\n"
    "--tls-ciphersuites l: A list of allowed TLS 1.3 cipher suites separated by : (optional)\n"
    "                : Use --show-tls to see a list of supported TLS ciphers (suites).\n"
    "--tls-cert-profile p : Set the allowed certificate crypto algorithm profile\n"
    "                  (default=legacy).\n"
    "--providers l   : A list l of OpenSSL providers to load.\n"
    "--tls-timeout n : Packet retransmit timeout on TLS control channel\n"
    "                  if no ACK from remote within n seconds (default=%d).\n"
    "--reneg-bytes n : Renegotiate data chan. key after n bytes sent and recvd.\n"
    "--reneg-pkts n  : Renegotiate data chan. key after n packets sent and recvd.\n"
    "--reneg-sec max [min] : Renegotiate data chan. key after at most max (default=%d)\n"
    "                  and at least min (defaults to 90%% of max on servers and equal\n"
    "                  to max on clients).\n"
    "--hand-window n : Data channel key exchange must finalize within n seconds\n"
    "                  of handshake initiation by any peer (default=%d).\n"
    "--tran-window n : Transition window -- old key can live this many seconds\n"
    "                  after new key renegotiation begins (default=%d).\n"
    "--single-session: Allow only one session (reset state on restart).\n"
    "--tls-exit      : Exit on TLS negotiation failure.\n"
    "--tls-auth f [d]: Add an additional layer of authentication on top of the TLS\n"
    "                  control channel to protect against attacks on the TLS stack\n"
    "                  and DoS attacks.\n"
    "                  f (required) is a shared-secret key file.\n"
    "                  The optional d parameter controls key directionality,\n"
    "                  see --secret option for more info.\n"
    "--tls-crypt key : Add an additional layer of authenticated encryption on top\n"
    "                  of the TLS control channel to hide the TLS certificate,\n"
    "                  provide basic post-quantum security and protect against\n"
    "                  attacks on the TLS stack and DoS attacks.\n"
    "                  key (required) provides the pre-shared key file.\n"
    "                  see --secret option for more info.\n"
    "--tls-crypt-v2 key : For clients: use key as a client-specific tls-crypt key.\n"
    "                  For servers: use key to decrypt client-specific keys.  For\n"
    "                  key generation (--genkey tls-crypt-v2-client): use key to\n"
    "                  encrypt generated client-specific key.  (See --tls-crypt.)\n"
    "--genkey tls-crypt-v2-client [keyfile] [base64 metadata]: Generate a\n"
    "                  fresh tls-crypt-v2 client key, and store to\n"
    "                  keyfile.  If supplied, include metadata in wrapped key.\n"
    "--genkey tls-crypt-v2-server [keyfile] [base64 metadata]: Generate a\n"
    "                  fresh tls-crypt-v2 server key, and store to keyfile\n"
    "--tls-crypt-v2-verify cmd : Run command cmd to verify the metadata of the\n"
    "                  client-supplied tls-crypt-v2 client key\n"
    "--askpass [file]: Get PEM password from controlling tty before we daemonize.\n"
    "--auth-nocache  : Don't cache --askpass or --auth-user-pass passwords.\n"
    "--crl-verify crl ['dir']: Check peer certificate against a CRL.\n"
    "--tls-verify cmd: Run command cmd to verify the X509 name of a\n"
    "                  pending TLS connection that has otherwise passed all other\n"
    "                  tests of certification.  cmd should return 0 to allow\n"
    "                  TLS handshake to proceed, or 1 to fail.  (cmd is\n"
    "                  executed as 'cmd certificate_depth subject')\n"
    "--verify-x509-name name: Accept connections only from a host with X509 subject\n"
    "                  DN name. The remote host must also pass all other tests\n"
    "                  of verification.\n"
#ifndef ENABLE_CRYPTO_MBEDTLS
    "--ns-cert-type t: (DEPRECATED) Require that peer certificate was signed with \n"
    "                  an explicit nsCertType designation t = 'client' | 'server'.\n"
#endif
    "--x509-track x  : Save peer X509 attribute x in environment for use by\n"
    "                  plugins and management interface.\n"
#ifdef HAVE_EXPORT_KEYING_MATERIAL
    "--keying-material-exporter label len : Save Exported Keying Material (RFC5705)\n"
    "                  of len bytes (min. 16 bytes) using label in environment for use by plugins.\n"
#endif
    "--remote-cert-ku v ... : Require that the peer certificate was signed with\n"
    "                  explicit key usage, you can specify more than one value.\n"
    "                  value should be given in hex format.\n"
    "--remote-cert-eku oid : Require that the peer certificate was signed with\n"
    "                  explicit extended key usage. Extended key usage can be encoded\n"
    "                  as an object identifier or OpenSSL string representation.\n"
    "--remote-cert-tls t: Require that peer certificate was signed with explicit\n"
    "                  key usage and extended key usage based on RFC3280 TLS rules.\n"
    "                  t = 'client' | 'server'.\n"
#ifdef ENABLE_PKCS11
    "\n"
    "PKCS#11 Options:\n"
    "--pkcs11-providers provider ... : PKCS#11 provider to load.\n"
    "--pkcs11-protected-authentication [0|1] ... : Use PKCS#11 protected authentication\n"
    "                              path. Set for each provider.\n"
    "--pkcs11-private-mode hex ...   : PKCS#11 private key mode mask.\n"
    "                              0       : Try  to determine automatically (default).\n"
    "                              1       : Use Sign.\n"
    "                              2       : Use SignRecover.\n"
    "                              4       : Use Decrypt.\n"
    "                              8       : Use Unwrap.\n"
    "--pkcs11-cert-private [0|1] ... : Set if login should be performed before\n"
    "                                  certificate can be accessed. Set for each provider.\n"
    "--pkcs11-pin-cache seconds      : Number of seconds to cache PIN. The default is -1\n"
    "                                  cache until token is removed.\n"
    "--pkcs11-id-management          : Acquire identity from management interface.\n"
    "--pkcs11-id serialized-id 'id'  : Identity to use, get using standalone --show-pkcs11-ids\n"
#endif                  /* ENABLE_PKCS11 */
    "\n"
    "SSL Library information:\n"
    "--show-ciphers  : Show cipher algorithms to use with --cipher option.\n"
    "--show-digests  : Show message digest algorithms to use with --auth option.\n"
    "--show-engines  : Show hardware crypto accelerator engines (if available).\n"
    "--show-tls      : Show all TLS ciphers (TLS used only as a control channel).\n"
#ifdef _WIN32
    "\n"
    "Windows Specific:\n"
    "--win-sys path    : Pathname of Windows system directory. Default is the pathname\n"
    "                    from SystemRoot environment variable.\n"
    "--ip-win32 method : When using --ifconfig on Windows, set TAP-Windows adapter\n"
    "                    IP address using method = manual, netsh, ipapi,\n"
    "                    dynamic, or adaptive (default = adaptive).\n"
    "                    Dynamic method allows two optional parameters:\n"
    "                    offset: DHCP server address offset (> -256 and < 256).\n"
    "                            If 0, use network address, if >0, take nth\n"
    "                            address forward from network address, if <0,\n"
    "                            take nth address backward from broadcast\n"
    "                            address.\n"
    "                            Default is 0.\n"
    "                    lease-time: Lease time in seconds.\n"
    "                                Default is one year.\n"
    "--route-method    : Which method to use for adding routes on Windows?\n"
    "                    adaptive (default) -- Try ipapi then fall back to exe.\n"
    "                    ipapi -- Use IP helper API.\n"
    "                    exe -- Call the route.exe shell command.\n"
    "--dhcp-option type [parm] : Set extended TAP-Windows properties, must\n"
    "                    be used with --ip-win32 dynamic.  For options\n"
    "                    which allow multiple addresses,\n"
    "                    --dhcp-option must be repeated.\n"
    "                    DOMAIN name : Set DNS suffix\n"
    "                    DOMAIN-SEARCH entry : Add entry to DNS domain search list\n"
    "                    DNS addr    : Set domain name server address(es) (IPv4 and IPv6)\n"
    "                    NTP         : Set NTP server address(es)\n"
    "                    NBDD        : Set NBDD server address(es)\n"
    "                    WINS addr   : Set WINS server address(es)\n"
    "                    NBT type    : Set NetBIOS over TCP/IP Node type\n"
    "                                  1: B, 2: P, 4: M, 8: H\n"
    "                    NBS id      : Set NetBIOS scope ID\n"
    "                    DISABLE-NBT : Disable Netbios-over-TCP/IP.\n"
    "--dhcp-renew       : Ask Windows to renew the TAP adapter lease on startup.\n"
    "--dhcp-pre-release : Ask Windows to release the previous TAP adapter lease on\n"
    "                       startup.\n"
    "--register-dns  : Run ipconfig /flushdns and ipconfig /registerdns\n"
    "                  on connection initiation.\n"
    "--tap-sleep n   : Sleep for n seconds after TAP adapter open before\n"
    "                  attempting to set adapter properties.\n"
    "--pause-exit         : When run from a console window, pause before exiting.\n"
    "--service ex [0|1]   : For use when " PACKAGE_NAME " is being instantiated by a\n"
    "                       service, and should not be used directly by end-users.\n"
    "                       ex is the name of an event object which, when\n"
    "                       signaled, will cause " PACKAGE_NAME " to exit.  A second\n"
    "                       optional parameter controls the initial state of ex.\n"
    "--show-net-up   : Show " PACKAGE_NAME "'s view of routing table and net adapter list\n"
    "                  after TAP adapter is up and routes have been added.\n"
    "--windows-driver   : Which tun driver to use?\n"
    "                     ovpn-dco (default)\n"
    "                     tap-windows6\n"
    "                     wintun\n"
    "--block-outside-dns   : Block DNS on other network adapters to prevent DNS leaks\n"
    "Windows Standalone Options:\n"
    "\n"
    "--show-adapters : Show all TAP-Windows adapters.\n"
    "--show-net      : Show " PACKAGE_NAME "'s view of routing table and net adapter list.\n"
    "--show-valid-subnets : Show valid subnets for --dev tun emulation.\n"
    "--allow-nonadmin [TAP-adapter] : Allow " PACKAGE_NAME " running without admin privileges\n"
    "                                 to access TAP adapter.\n"
#endif /* ifdef _WIN32 */
    "\n"
    "Generate a new key :\n"
    "--genkey secret file   : Generate a new random key of type and write to file\n"
    "                         (for use with --secret, --tls-auth or --tls-crypt)."
#ifdef ENABLE_FEATURE_TUN_PERSIST
    "\n"
    "Tun/tap config mode (available with linux 2.4+):\n"
    "--mktun         : Create a persistent tunnel.\n"
    "--rmtun         : Remove a persistent tunnel.\n"
    "--dev tunX|tapX : tun/tap device\n"
    "--dev-type dt   : Device type.  See tunnel options above for details.\n"
    "--user user     : User to set privilege to.\n"
    "--group group   : Group to set privilege to.\n"
#endif
#ifdef ENABLE_PKCS11
    "\n"
    "PKCS#11 standalone options:\n"
#ifdef DEFAULT_PKCS11_MODULE
    "--show-pkcs11-ids [provider] [cert_private] : Show PKCS#11 available ids.\n"
#else
    "--show-pkcs11-ids provider [cert_private] : Show PKCS#11 available ids.\n"
#endif
    "                                            --verb option can be added *BEFORE* this.\n"
#endif                          /* ENABLE_PKCS11 */
    "\n"
    "General Standalone Options:\n"
#ifdef ENABLE_DEBUG
    "--show-gateway : Show info about default gateway.\n"
#endif
;

#endif /* !ENABLE_SMALL */

/*
 * This is where the options defaults go.
 * Any option not explicitly set here
 * will be set to 0.
 */
void
init_options(struct options *o, const bool init_gc)
{
    CLEAR(*o);
    if (init_gc)
    {
        gc_init(&o->gc);
        gc_init(&o->dns_options.gc);
        o->gc_owned = true;
    }
    o->mode = MODE_POINT_TO_POINT;
    o->topology = TOP_NET30;
    o->ce.proto = PROTO_UDP;
    o->ce.af = AF_UNSPEC;
    o->ce.bind_ipv6_only = false;
    o->ce.connect_retry_seconds = 1;
    o->ce.connect_retry_seconds_max = 300;
    o->ce.connect_timeout = 120;
    o->connect_retry_max = 0;
    o->ce.local_port = o->ce.remote_port = OPENVPN_PORT;
    o->verbosity = 1;
    o->status_file_update_freq = 60;
    o->status_file_version = 1;
    o->ce.bind_local = true;
    o->ce.tun_mtu = TUN_MTU_DEFAULT;
    o->ce.occ_mtu = 0;
    o->ce.link_mtu = LINK_MTU_DEFAULT;
    o->ce.tls_mtu = TLS_MTU_DEFAULT;
    o->ce.mtu_discover_type = -1;
    o->ce.mssfix = 0;
    o->ce.mssfix_default = true;
    o->ce.mssfix_encap = true;
    o->route_delay_window = 30;
    o->resolve_retry_seconds = RESOLV_RETRY_INFINITE;
    o->resolve_in_advance = false;
    o->proto_force = -1;
    o->occ = true;
#ifdef ENABLE_MANAGEMENT
    o->management_log_history_cache = 250;
    o->management_echo_buffer_size = 100;
    o->management_state_buffer_size = 100;
#endif
#ifdef ENABLE_FEATURE_TUN_PERSIST
    o->persist_mode = 1;
#endif
#ifdef _WIN32
#if 0
    o->tuntap_options.ip_win32_type = IPW32_SET_ADAPTIVE;
#else
    o->tuntap_options.ip_win32_type = IPW32_SET_DHCP_MASQ;
#endif
    o->tuntap_options.dhcp_lease_time = 31536000; /* one year */
    o->tuntap_options.dhcp_masq_offset = 0;     /* use network address as internal DHCP server address */
    o->route_method = ROUTE_METHOD_ADAPTIVE;
    o->block_outside_dns = false;
    o->windows_driver = WINDOWS_DRIVER_UNSPECIFIED;
#endif
    o->vlan_accept = VLAN_ALL;
    o->vlan_pvid = 1;
    o->real_hash_size = 256;
    o->virtual_hash_size = 256;
    o->n_bcast_buf = 256;
    o->tcp_queue_limit = 64;
    o->max_clients = 1024;
    o->cf_initial_per = 10;
    o->cf_initial_max = 100;
    o->max_routes_per_client = 256;
    o->stale_routes_check_interval = 0;
    o->ifconfig_pool_persist_refresh_freq = 600;
    o->scheduled_exit_interval = 5;
    o->authname = "SHA1";
    o->replay = true;
    o->replay_window = DEFAULT_SEQ_BACKTRACK;
    o->replay_time = DEFAULT_TIME_BACKTRACK;
    o->key_direction = KEY_DIRECTION_BIDIRECTIONAL;
#ifdef ENABLE_PREDICTION_RESISTANCE
    o->use_prediction_resistance = false;
#endif
    o->tls_timeout = 2;
    o->renegotiate_bytes = -1;
    o->renegotiate_seconds = 3600;
    o->renegotiate_seconds_min = -1;
    o->handshake_window = 60;
    o->transition_window = 3600;
    o->tls_cert_profile = NULL;
    o->ecdh_curve = NULL;
#ifdef ENABLE_X509ALTUSERNAME
    o->x509_username_field[0] = X509_USERNAME_FIELD_DEFAULT;
#endif
#ifdef ENABLE_PKCS11
    o->pkcs11_pin_cache_period = -1;
#endif                  /* ENABLE_PKCS11 */

/* P2MP server context features */
    o->auth_token_generate = false;

    /* Set default --tmp-dir */
#ifdef _WIN32
    /* On Windows, find temp dir via environment variables */
    o->tmp_dir = win_get_tempdir();
#else
    /* Non-windows platforms use $TMPDIR, and if not set, default to '/tmp' */
    o->tmp_dir = getenv("TMPDIR");
    if (!o->tmp_dir)
    {
        o->tmp_dir = "/tmp";
    }
#endif /* _WIN32 */
    o->allow_recursive_routing = false;

#ifndef ENABLE_DCO
    o->tuntap_options.disable_dco = true;
#endif /* ENABLE_DCO */
}

void
uninit_options(struct options *o)
{
    if (o->connection_list)
    {
        CLEAR(*o->connection_list);
    }
    if (o->remote_list)
    {
        CLEAR(*o->remote_list);
    }
    if (o->gc_owned)
    {
        gc_free(&o->gc);
        gc_free(&o->dns_options.gc);
    }
}

struct pull_filter
{
#define PUF_TYPE_UNDEF  0    /** undefined filter type */
#define PUF_TYPE_ACCEPT 1    /** filter type to accept a matching option */
#define PUF_TYPE_IGNORE 2    /** filter type to ignore a matching option */
#define PUF_TYPE_REJECT 3    /** filter type to reject and trigger SIGUSR1 */
    int type;
    int size;
    char *pattern;
    struct pull_filter *next;
};

struct pull_filter_list
{
    struct pull_filter *head;
    struct pull_filter *tail;
};

#ifndef ENABLE_SMALL

static const char *
pull_filter_type_name(int type)
{
    if (type == PUF_TYPE_ACCEPT)
    {
        return "accept";
    }
    if (type == PUF_TYPE_IGNORE)
    {
        return "ignore";
    }
    if (type == PUF_TYPE_REJECT)
    {
        return "reject";
    }
    else
    {
        return "???";
    }
}

#define SHOW_PARM(name, value, format) msg(D_SHOW_PARMS, "  " #name " = " format, (value))
#define SHOW_STR(var)       SHOW_PARM(var, (o->var ? o->var : "[UNDEF]"), "'%s'")
#define SHOW_STR_INLINE(var)    SHOW_PARM(var, \
                                          o->var ## _inline ? "[INLINE]" : \
                                          (o->var ? o->var : "[UNDEF]"), \
                                          "'%s'")
#define SHOW_INT(var)       SHOW_PARM(var, o->var, "%d")
#define SHOW_UINT(var)      SHOW_PARM(var, o->var, "%u")
#define SHOW_INT64(var)     SHOW_PARM(var, o->var, "%" PRIi64)
#define SHOW_UNSIGNED(var)  SHOW_PARM(var, o->var, "0x%08x")
#define SHOW_BOOL(var)      SHOW_PARM(var, (o->var ? "ENABLED" : "DISABLED"), "%s");

#endif /* ifndef ENABLE_SMALL */

static void
setenv_connection_entry(struct env_set *es,
                        const struct connection_entry *e,
                        const int i)
{
    setenv_str_i(es, "proto", proto2ascii(e->proto, e->af, false), i);
    setenv_str_i(es, "local", e->local, i);
    setenv_str_i(es, "local_port", e->local_port, i);
    setenv_str_i(es, "remote", e->remote, i);
    setenv_str_i(es, "remote_port", e->remote_port, i);

    if (e->http_proxy_options)
    {
        setenv_str_i(es, "http_proxy_server", e->http_proxy_options->server, i);
        setenv_str_i(es, "http_proxy_port", e->http_proxy_options->port, i);
    }
    if (e->socks_proxy_server)
    {
        setenv_str_i(es, "socks_proxy_server", e->socks_proxy_server, i);
        setenv_str_i(es, "socks_proxy_port", e->socks_proxy_port, i);
    }
}

void
setenv_settings(struct env_set *es, const struct options *o)
{
    setenv_str(es, "config", o->config);
    setenv_int(es, "verb", o->verbosity);
    setenv_int(es, "daemon", o->daemon);
    setenv_int(es, "daemon_log_redirect", o->log);
    setenv_long_long(es, "daemon_start_time", time(NULL));
    setenv_int(es, "daemon_pid", platform_getpid());

    if (o->connection_list)
    {
        int i;
        for (i = 0; i < o->connection_list->len; ++i)
        {
            setenv_connection_entry(es, o->connection_list->array[i], i+1);
        }
    }
    else
    {
        setenv_connection_entry(es, &o->ce, 1);
    }

    if (!o->pull)
    {
        setenv_dns_options(&o->dns_options, es);
    }
}

#ifndef _WIN32
static void
setenv_foreign_option(struct options *o, const char *argv[], int len, struct env_set *es)
{
    if (len > 0)
    {
        struct gc_arena gc = gc_new();
        struct buffer name = alloc_buf_gc(OPTION_PARM_SIZE, &gc);
        struct buffer value = alloc_buf_gc(OPTION_PARM_SIZE, &gc);
        int i;
        bool first = true;
        bool good = true;

        good &= buf_printf(&name, "foreign_option_%d", o->foreign_option_index + 1);
        ++o->foreign_option_index;
        for (i = 0; i < len; ++i)
        {
            if (argv[i])
            {
                if (!first)
                {
                    good &= buf_printf(&value, " ");
                }
                good &= buf_printf(&value, "%s", argv[i]);
                first = false;
            }
        }
        if (good)
        {
            setenv_str(es, BSTR(&name), BSTR(&value));
        }
        else
        {
            msg(M_WARN, "foreign_option: name/value overflow");
        }
        gc_free(&gc);
    }
}
#endif /* ifndef _WIN32 */

static in_addr_t
get_ip_addr(const char *ip_string, int msglevel, bool *error)
{
    unsigned int flags = GETADDR_HOST_ORDER;
    bool succeeded = false;
    in_addr_t ret;

    if (msglevel & M_FATAL)
    {
        flags |= GETADDR_FATAL;
    }

    ret = getaddr(flags, ip_string, 0, &succeeded, NULL);
    if (!succeeded && error)
    {
        *error = true;
    }
    return ret;
}

/**
 * Returns newly allocated string containing address part without "/nn".
 *
 * If gc != NULL, the allocated memory is registered in the supplied gc.
 */
static char *
get_ipv6_addr_no_netbits(const char *addr, struct gc_arena *gc)
{
    const char *end = strchr(addr, '/');
    char *ret = NULL;
    if (NULL == end)
    {
        ret = string_alloc(addr, gc);
    }
    else
    {
        size_t len = end - addr;
        ret = gc_malloc(len + 1, true, gc);
        memcpy(ret, addr, len);
    }
    return ret;
}

static bool
ipv6_addr_safe_hexplusbits( const char *ipv6_prefix_spec )
{
    struct in6_addr t_addr;
    unsigned int t_bits;

    return get_ipv6_addr( ipv6_prefix_spec, &t_addr, &t_bits, M_WARN );
}

static char *
string_substitute(const char *src, int from, int to, struct gc_arena *gc)
{
    char *ret = (char *) gc_malloc(strlen(src) + 1, true, gc);
    char *dest = ret;
    char c;

    do
    {
        c = *src++;
        if (c == from)
        {
            c = to;
        }
        *dest++ = c;
    }
    while (c);
    return ret;
}

/**
 * Parses a hexstring and checks if the string has the correct length. Return
 * a verify_hash_list containing the parsed hash string.
 *
 * @param   str         String to check/parse
 * @param   nbytes      Number of bytes expected in the hexstr (e.g. 20 for SHA1)
 * @param   msglevel    message level to use when printing warnings/errors
 * @param   gc          The returned object will be allocated in this gc
 */
static struct verify_hash_list *
parse_hash_fingerprint(const char *str, int nbytes, int msglevel, struct gc_arena *gc)
{
    int i = 0;
    const char *cp = str;

    struct verify_hash_list *ret;
    ALLOC_OBJ_CLEAR_GC(ret, struct verify_hash_list, gc);

    char term = 0;
    unsigned int byte;

    while (*cp && i < nbytes)
    {
        /* valid segments consist of exactly two hex digits, then ':' or EOS */
        if (!isxdigit(cp[0])
            || !isxdigit(cp[1])
            || (cp[2] != ':' && cp[2] != '\0')
            || sscanf(cp, "%x", &byte) != 1)
        {
            msg(msglevel, "format error in hash fingerprint: %s", str);
            break;
        }

        ret->hash[i++] = (uint8_t)byte;

        term = cp[2];
        if (term == '\0')
        {
            break;
        }
        cp += 3;
    }
    if (i < nbytes)
    {
        msg(msglevel, "hash fingerprint is wrong length - expected %d bytes, got %d: %s", nbytes, i, str);
    }
    else if (term != '\0')
    {
        msg(msglevel, "hash fingerprint too long - expected only %d bytes: %s", nbytes, str);
    }
    return ret;
}

/**
 * Parses a string consisting of multiple lines of hexstrings and checks if each
 * string has the correct length. Empty lines are ignored. Returns
 * a linked list of (possibly) multiple verify_hash_list objects.
 *
 * @param   str         String to check/parse
 * @param   nbytes      Number of bytes expected in the hexstring (e.g. 20 for SHA1)
 * @param   msglevel    message level to use when printing warnings/errors
 * @param   gc          The returned list items will be allocated in this gc
 */
static struct verify_hash_list *
parse_hash_fingerprint_multiline(const char *str, int nbytes, int msglevel,
                                 struct gc_arena *gc)
{
    struct gc_arena gc_temp = gc_new();
    char *lines = string_alloc(str, &gc_temp);

    struct verify_hash_list *ret = NULL;

    const char *line;
    while ((line = strsep(&lines, "\n")))
    {
        /* ignore leading whitespace */
        while (isspace(*line))
        {
            line++;
        }
        /* skip empty lines and comment lines */
        if (strlen(line) == 0 || *line == '#' || *line == ';')
        {
            continue;
        }

        struct verify_hash_list *hash = parse_hash_fingerprint(line, nbytes,
                                                               msglevel, gc);

        if (!hash)
        {
            gc_free(&gc_temp);
            return NULL;
        }

        hash->next = ret;
        ret = hash;
    }
    gc_free(&gc_temp);

    return ret;
}
#ifdef _WIN32

#ifndef ENABLE_SMALL

static void
show_dhcp_option_list(const char *name, const char *const *array, int len)
{
    int i;
    for (i = 0; i < len; ++i)
    {
        msg(D_SHOW_PARMS, "  %s[%d] = %s", name, i, array[i] );
    }
}

static void
show_dhcp_option_addrs(const char *name, const in_addr_t *array, int len)
{
    struct gc_arena gc = gc_new();
    int i;
    for (i = 0; i < len; ++i)
    {
        msg(D_SHOW_PARMS, "  %s[%d] = %s",
            name,
            i,
            print_in_addr_t(array[i], 0, &gc));
    }
    gc_free(&gc);
}

static void
show_tuntap_options(const struct tuntap_options *o)
{
    SHOW_BOOL(ip_win32_defined);
    SHOW_INT(ip_win32_type);
    SHOW_INT(dhcp_masq_offset);
    SHOW_INT(dhcp_lease_time);
    SHOW_INT(tap_sleep);
    SHOW_UNSIGNED(dhcp_options);
    SHOW_BOOL(dhcp_renew);
    SHOW_BOOL(dhcp_pre_release);
    SHOW_STR(domain);
    SHOW_STR(netbios_scope);
    SHOW_INT(netbios_node_type);
    SHOW_BOOL(disable_nbt);

    show_dhcp_option_addrs("DNS", o->dns, o->dns_len);
    show_dhcp_option_addrs("WINS", o->wins, o->wins_len);
    show_dhcp_option_addrs("NTP", o->ntp, o->ntp_len);
    show_dhcp_option_addrs("NBDD", o->nbdd, o->nbdd_len);
    show_dhcp_option_list("DOMAIN-SEARCH", o->domain_search_list, o->domain_search_list_len);
}

#endif /* ifndef ENABLE_SMALL */
#endif /* ifdef _WIN32 */

#if defined(_WIN32) || defined(TARGET_ANDROID)
static void
dhcp_option_dns6_parse(const char *parm, struct in6_addr *dns6_list, int *len, int msglevel)
{
    struct in6_addr addr;
    if (*len >= N_DHCP_ADDR)
    {
        msg(msglevel, "--dhcp-option DNS: maximum of %d IPv6 dns servers can be specified",
            N_DHCP_ADDR);
    }
    else if (get_ipv6_addr(parm, &addr, NULL, msglevel))
    {
        dns6_list[(*len)++] = addr;
    }
}
static void
dhcp_option_address_parse(const char *name, const char *parm, in_addr_t *array, int *len, int msglevel)
{
    if (*len >= N_DHCP_ADDR)
    {
        msg(msglevel, "--dhcp-option %s: maximum of %d %s servers can be specified",
            name,
            N_DHCP_ADDR,
            name);
    }
    else
    {
        if (ip_addr_dotted_quad_safe(parm)) /* FQDN -- IP address only */
        {
            bool error = false;
            const in_addr_t addr = get_ip_addr(parm, msglevel, &error);
            if (!error)
            {
                array[(*len)++] = addr;
            }
        }
        else
        {
            msg(msglevel, "dhcp-option parameter %s '%s' must be an IP address", name, parm);
        }
    }
}

/*
 * If DNS options are set use these for TUN/TAP options as well.
 * Applies to DNS, DNS6 and DOMAIN-SEARCH.
 * Existing options will be discarded.
 */
static void
tuntap_options_copy_dns(struct options *o)
{
    struct tuntap_options *tt = &o->tuntap_options;
    struct dns_options *dns = &o->dns_options;

    if (dns->search_domains)
    {
        tt->domain_search_list_len = 0;
        const struct dns_domain *domain = dns->search_domains;
        while (domain && tt->domain_search_list_len < N_SEARCH_LIST_LEN)
        {
            tt->domain_search_list[tt->domain_search_list_len++] = domain->name;
            domain = domain->next;
        }
        if (domain)
        {
            msg(M_WARN, "WARNING: couldn't copy all --dns search-domains to --dhcp-option");
        }
        tt->dhcp_options |= DHCP_OPTIONS_DHCP_REQUIRED;
    }

    if (dns->servers)
    {
        tt->dns_len = 0;
        tt->dns6_len = 0;
        bool overflow = false;
        const struct dns_server *server = dns->servers;
        while (server)
        {
            for (int i = 0; i < server->addr_count; ++i)
            {
                if (server->addr[i].family == AF_INET)
                {
                    if (tt->dns_len >= N_DHCP_ADDR)
                    {
                        overflow = true;
                        continue;
                    }
                    tt->dns[tt->dns_len++] = server->addr[i].in.a4.s_addr;
                }
                else
                {
                    if (tt->dns6_len >= N_DHCP_ADDR)
                    {
                        overflow = true;
                        continue;
                    }
                    tt->dns6[tt->dns6_len++] = server->addr[i].in.a6;
                }
            }
            server = server->next;
        }
        if (overflow)
        {
            msg(M_WARN, "WARNING: couldn't copy all --dns server addresses to --dhcp-option");
        }
        tt->dhcp_options |= DHCP_OPTIONS_DHCP_OPTIONAL;
    }
}
#else /* if defined(_WIN32) || defined(TARGET_ANDROID) */
static void
foreign_options_copy_dns(struct options *o, struct env_set *es)
{
    const struct dns_domain *domain = o->dns_options.search_domains;
    const struct dns_server *server = o->dns_options.servers;
    if (!domain && !server)
    {
        return;
    }

    /* reset the index since we're starting all over again */
    int opt_max = o->foreign_option_index;
    o->foreign_option_index = 0;

    for (int i = 1; i <= opt_max; ++i)
    {
        char name[32];
        openvpn_snprintf(name, sizeof(name), "foreign_option_%d", i);

        const char *env_str = env_set_get(es, name);
        const char *value = strchr(env_str, '=') + 1;
        if ((domain && strstr(value, "dhcp-option DOMAIN-SEARCH") == value)
            || (server && strstr(value, "dhcp-option DNS") == value))
        {
            setenv_del(es, name);
        }
        else
        {
            setenv_foreign_option(o, &value, 1, es);
        }
    }

    struct gc_arena gc = gc_new();

    while (server)
    {
        for (int i = 0; i < server->addr_count; ++i)
        {
            if (server->addr[i].family == AF_INET)
            {
                const char *argv[] = {
                    "dhcp-option",
                    "DNS",
                    print_in_addr_t(server->addr[i].in.a4.s_addr, 0, &gc)
                };
                setenv_foreign_option(o, argv, 3, es);
            }
            else
            {
                const char *argv[] = {
                    "dhcp-option",
                    "DNS6",
                    print_in6_addr(server->addr[i].in.a6, 0, &gc)
                };
                setenv_foreign_option(o, argv, 3, es);
            }
        }
        server = server->next;
    }
    while (domain)
    {
        const char *argv[] = { "dhcp-option", "DOMAIN-SEARCH", domain->name };
        setenv_foreign_option(o, argv, 3, es);
        domain = domain->next;
    }

    gc_free(&gc);

    /* remove old leftover entries */
    while (o->foreign_option_index < opt_max)
    {
        char name[32];
        openvpn_snprintf(name, sizeof(name), "foreign_option_%d", opt_max--);
        setenv_del(es, name);
    }
}
#endif /* if defined(_WIN32) || defined(TARGET_ANDROID) */

#ifndef ENABLE_SMALL
static const char *
print_vlan_accept(enum vlan_acceptable_frames mode)
{
    switch (mode)
    {
        case VLAN_ONLY_TAGGED:
            return "tagged";

        case VLAN_ONLY_UNTAGGED_OR_PRIORITY:
            return "untagged";

        case VLAN_ALL:
            return "all";
    }
    return NULL;
}

static void
show_p2mp_parms(const struct options *o)
{
    struct gc_arena gc = gc_new();

    msg(D_SHOW_PARMS, "  server_network = %s", print_in_addr_t(o->server_network, 0, &gc));
    msg(D_SHOW_PARMS, "  server_netmask = %s", print_in_addr_t(o->server_netmask, 0, &gc));
    msg(D_SHOW_PARMS, "  server_network_ipv6 = %s", print_in6_addr(o->server_network_ipv6, 0, &gc) );
    SHOW_INT(server_netbits_ipv6);
    msg(D_SHOW_PARMS, "  server_bridge_ip = %s", print_in_addr_t(o->server_bridge_ip, 0, &gc));
    msg(D_SHOW_PARMS, "  server_bridge_netmask = %s", print_in_addr_t(o->server_bridge_netmask, 0, &gc));
    msg(D_SHOW_PARMS, "  server_bridge_pool_start = %s", print_in_addr_t(o->server_bridge_pool_start, 0, &gc));
    msg(D_SHOW_PARMS, "  server_bridge_pool_end = %s", print_in_addr_t(o->server_bridge_pool_end, 0, &gc));
    if (o->push_list.head)
    {
        const struct push_entry *e = o->push_list.head;
        while (e)
        {
            if (e->enable)
            {
                msg(D_SHOW_PARMS, "  push_entry = '%s'", e->option);
            }
            e = e->next;
        }
    }
    SHOW_BOOL(ifconfig_pool_defined);
    msg(D_SHOW_PARMS, "  ifconfig_pool_start = %s", print_in_addr_t(o->ifconfig_pool_start, 0, &gc));
    msg(D_SHOW_PARMS, "  ifconfig_pool_end = %s", print_in_addr_t(o->ifconfig_pool_end, 0, &gc));
    msg(D_SHOW_PARMS, "  ifconfig_pool_netmask = %s", print_in_addr_t(o->ifconfig_pool_netmask, 0, &gc));
    SHOW_STR(ifconfig_pool_persist_filename);
    SHOW_INT(ifconfig_pool_persist_refresh_freq);
    SHOW_BOOL(ifconfig_ipv6_pool_defined);
    msg(D_SHOW_PARMS, "  ifconfig_ipv6_pool_base = %s", print_in6_addr(o->ifconfig_ipv6_pool_base, 0, &gc));
    SHOW_INT(ifconfig_ipv6_pool_netbits);
    SHOW_INT(n_bcast_buf);
    SHOW_INT(tcp_queue_limit);
    SHOW_INT(real_hash_size);
    SHOW_INT(virtual_hash_size);
    SHOW_STR(client_connect_script);
    SHOW_STR(learn_address_script);
    SHOW_STR(client_disconnect_script);
    SHOW_STR(client_crresponse_script);
    SHOW_STR(client_config_dir);
    SHOW_BOOL(ccd_exclusive);
    SHOW_STR(tmp_dir);
    SHOW_BOOL(push_ifconfig_defined);
    msg(D_SHOW_PARMS, "  push_ifconfig_local = %s", print_in_addr_t(o->push_ifconfig_local, 0, &gc));
    msg(D_SHOW_PARMS, "  push_ifconfig_remote_netmask = %s", print_in_addr_t(o->push_ifconfig_remote_netmask, 0, &gc));
    SHOW_BOOL(push_ifconfig_ipv6_defined);
    msg(D_SHOW_PARMS, "  push_ifconfig_ipv6_local = %s/%d", print_in6_addr(o->push_ifconfig_ipv6_local, 0, &gc), o->push_ifconfig_ipv6_netbits );
    msg(D_SHOW_PARMS, "  push_ifconfig_ipv6_remote = %s", print_in6_addr(o->push_ifconfig_ipv6_remote, 0, &gc));
    SHOW_BOOL(enable_c2c);
    SHOW_BOOL(duplicate_cn);
    SHOW_INT(cf_max);
    SHOW_INT(cf_per);
    SHOW_INT(cf_initial_max);
    SHOW_INT(cf_initial_per);
    SHOW_INT(max_clients);
    SHOW_INT(max_routes_per_client);
    SHOW_STR(auth_user_pass_verify_script);
    SHOW_BOOL(auth_user_pass_verify_script_via_file);
    SHOW_BOOL(auth_token_generate);
    SHOW_BOOL(force_key_material_export);
    SHOW_INT(auth_token_lifetime);
    SHOW_STR_INLINE(auth_token_secret_file);
#if PORT_SHARE
    SHOW_STR(port_share_host);
    SHOW_STR(port_share_port);
#endif
    SHOW_BOOL(vlan_tagging);
    msg(D_SHOW_PARMS, "  vlan_accept = %s", print_vlan_accept(o->vlan_accept));
    SHOW_INT(vlan_pvid);

    SHOW_BOOL(client);
    SHOW_BOOL(pull);
    SHOW_STR_INLINE(auth_user_pass_file);

    gc_free(&gc);
}

#endif /* ! ENABLE_SMALL */

static void
option_iroute(struct options *o,
              const char *network_str,
              const char *netmask_str,
              int msglevel)
{
    struct iroute *ir;

    ALLOC_OBJ_GC(ir, struct iroute, &o->gc);
    ir->network = getaddr(GETADDR_HOST_ORDER, network_str, 0, NULL, NULL);
    ir->netbits = 32;           /* host route if no netmask given */

    if (netmask_str)
    {
        const in_addr_t netmask = getaddr(GETADDR_HOST_ORDER, netmask_str, 0, NULL, NULL);
        ir->netbits = netmask_to_netbits2(netmask);

        if (ir->netbits < 0)
        {
            msg(msglevel, "in --iroute %s %s : Bad network/subnet specification",
                network_str,
                netmask_str);
            return;
        }
    }

    ir->next = o->iroutes;
    o->iroutes = ir;
}

static void
option_iroute_ipv6(struct options *o,
                   const char *prefix_str,
                   int msglevel)
{
    struct iroute_ipv6 *ir;

    ALLOC_OBJ_GC(ir, struct iroute_ipv6, &o->gc);

    if (!get_ipv6_addr(prefix_str, &ir->network, &ir->netbits, msglevel ))
    {
        msg(msglevel, "in --iroute-ipv6 %s: Bad IPv6 prefix specification",
            prefix_str);
        return;
    }

    ir->next = o->iroutes_ipv6;
    o->iroutes_ipv6 = ir;
}

#ifndef ENABLE_SMALL
static void
show_http_proxy_options(const struct http_proxy_options *o)
{
    int i;
    msg(D_SHOW_PARMS, "BEGIN http_proxy");
    SHOW_STR(server);
    SHOW_STR(port);
    SHOW_STR(auth_method_string);
    SHOW_STR(auth_file);
    SHOW_STR(auth_file_up);
    SHOW_BOOL(inline_creds);
    SHOW_BOOL(nocache);
    SHOW_STR(http_version);
    SHOW_STR(user_agent);
    for  (i = 0; i < MAX_CUSTOM_HTTP_HEADER && o->custom_headers[i].name; i++)
    {
        if (o->custom_headers[i].content)
        {
            msg(D_SHOW_PARMS, "  custom_header[%d] = %s: %s", i,
                o->custom_headers[i].name, o->custom_headers[i].content);
        }
        else
        {
            msg(D_SHOW_PARMS, "  custom_header[%d] = %s", i,
                o->custom_headers[i].name);
        }
    }
    msg(D_SHOW_PARMS, "END http_proxy");
}
#endif /* ifndef ENABLE_SMALL */

void
options_detach(struct options *o)
{
    gc_detach(&o->gc);
    o->routes = NULL;
    o->client_nat = NULL;
    clone_push_list(o);
}

void
rol_check_alloc(struct options *options)
{
    if (!options->routes)
    {
        options->routes = new_route_option_list(&options->gc);
    }
}

static void
rol6_check_alloc(struct options *options)
{
    if (!options->routes_ipv6)
    {
        options->routes_ipv6 = new_route_ipv6_option_list(&options->gc);
    }
}

static void
cnol_check_alloc(struct options *options)
{
    if (!options->client_nat)
    {
        options->client_nat = new_client_nat_list(&options->gc);
    }
}

#ifndef ENABLE_SMALL
static void
show_connection_entry(const struct connection_entry *o)
{
    msg(D_SHOW_PARMS, "  proto = %s", proto2ascii(o->proto, o->af, false));
    SHOW_STR(local);
    SHOW_STR(local_port);
    SHOW_STR(remote);
    SHOW_STR(remote_port);
    SHOW_BOOL(remote_float);
    SHOW_BOOL(bind_defined);
    SHOW_BOOL(bind_local);
    SHOW_BOOL(bind_ipv6_only);
    SHOW_INT(connect_retry_seconds);
    SHOW_INT(connect_timeout);

    if (o->http_proxy_options)
    {
        show_http_proxy_options(o->http_proxy_options);
    }
    SHOW_STR(socks_proxy_server);
    SHOW_STR(socks_proxy_port);
    SHOW_INT(tun_mtu);
    SHOW_BOOL(tun_mtu_defined);
    SHOW_INT(link_mtu);
    SHOW_BOOL(link_mtu_defined);
    SHOW_INT(tun_mtu_extra);
    SHOW_BOOL(tun_mtu_extra_defined);
    SHOW_INT(tls_mtu);

    SHOW_INT(mtu_discover_type);

#ifdef ENABLE_FRAGMENT
    SHOW_INT(fragment);
#endif
    SHOW_INT(mssfix);
    SHOW_BOOL(mssfix_encap);
    SHOW_BOOL(mssfix_fixed);

    SHOW_INT(explicit_exit_notification);

    SHOW_STR_INLINE(tls_auth_file);
    SHOW_PARM(key_direction, keydirection2ascii(o->key_direction, false, true),
              "%s");
    SHOW_STR_INLINE(tls_crypt_file);
    SHOW_STR_INLINE(tls_crypt_v2_file);
}


static void
show_connection_entries(const struct options *o)
{
    if (o->connection_list)
    {
        const struct connection_list *l = o->connection_list;
        int i;
        for (i = 0; i < l->len; ++i)
        {
            msg(D_SHOW_PARMS, "Connection profiles [%d]:", i);
            show_connection_entry(l->array[i]);
        }
    }
    else
    {
        msg(D_SHOW_PARMS, "Connection profiles [default]:");
        show_connection_entry(&o->ce);
    }
    msg(D_SHOW_PARMS, "Connection profiles END");
}

static void
show_pull_filter_list(const struct pull_filter_list *l)
{
    struct pull_filter *f;
    if (!l)
    {
        return;
    }

    msg(D_SHOW_PARMS, "  Pull filters:");
    for (f = l->head; f; f = f->next)
    {
        msg(D_SHOW_PARMS, "    %s \"%s\"", pull_filter_type_name(f->type), f->pattern);
    }
}

#endif /* ifndef ENABLE_SMALL */

void
show_settings(const struct options *o)
{
#ifndef ENABLE_SMALL
    msg(D_SHOW_PARMS, "Current Parameter Settings:");

    SHOW_STR(config);

    SHOW_INT(mode);

#ifdef ENABLE_FEATURE_TUN_PERSIST
    SHOW_BOOL(persist_config);
    SHOW_INT(persist_mode);
#endif

    SHOW_BOOL(show_ciphers);
    SHOW_BOOL(show_digests);
    SHOW_BOOL(show_engines);
    SHOW_BOOL(genkey);
    SHOW_STR(genkey_filename);
    SHOW_STR(key_pass_file);
    SHOW_BOOL(show_tls_ciphers);

    SHOW_INT(connect_retry_max);
    show_connection_entries(o);

    SHOW_BOOL(remote_random);

    SHOW_STR(ipchange);
    SHOW_STR(dev);
    SHOW_STR(dev_type);
    SHOW_STR(dev_node);
#if defined(ENABLE_DCO)
    SHOW_BOOL(tuntap_options.disable_dco);
#endif
    SHOW_STR(lladdr);
    SHOW_INT(topology);
    SHOW_STR(ifconfig_local);
    SHOW_STR(ifconfig_remote_netmask);
    SHOW_BOOL(ifconfig_noexec);
    SHOW_BOOL(ifconfig_nowarn);
    SHOW_STR(ifconfig_ipv6_local);
    SHOW_INT(ifconfig_ipv6_netbits);
    SHOW_STR(ifconfig_ipv6_remote);

    SHOW_INT(shaper);
    SHOW_INT(mtu_test);

    SHOW_BOOL(mlock);

    SHOW_INT(keepalive_ping);
    SHOW_INT(keepalive_timeout);
    SHOW_INT(inactivity_timeout);
    SHOW_INT(session_timeout);
    SHOW_INT64(inactivity_minimum_bytes);
    SHOW_INT(ping_send_timeout);
    SHOW_INT(ping_rec_timeout);
    SHOW_INT(ping_rec_timeout_action);
    SHOW_BOOL(ping_timer_remote);
    SHOW_INT(remap_sigusr1);
    SHOW_BOOL(persist_tun);
    SHOW_BOOL(persist_local_ip);
    SHOW_BOOL(persist_remote_ip);
    SHOW_BOOL(persist_key);

#if PASSTOS_CAPABILITY
    SHOW_BOOL(passtos);
#endif

    SHOW_INT(resolve_retry_seconds);
    SHOW_BOOL(resolve_in_advance);

    SHOW_STR(username);
    SHOW_STR(groupname);
    SHOW_STR(chroot_dir);
    SHOW_STR(cd_dir);
#ifdef ENABLE_SELINUX
    SHOW_STR(selinux_context);
#endif
    SHOW_STR(writepid);
    SHOW_STR(up_script);
    SHOW_STR(down_script);
    SHOW_BOOL(down_pre);
    SHOW_BOOL(up_restart);
    SHOW_BOOL(up_delay);
    SHOW_BOOL(daemon);
    SHOW_BOOL(log);
    SHOW_BOOL(suppress_timestamps);
    SHOW_BOOL(machine_readable_output);
    SHOW_INT(nice);
    SHOW_INT(verbosity);
    SHOW_INT(mute);
#ifdef ENABLE_DEBUG
    SHOW_INT(gremlin);
#endif
    SHOW_STR(status_file);
    SHOW_INT(status_file_version);
    SHOW_INT(status_file_update_freq);

    SHOW_BOOL(occ);
    SHOW_INT(rcvbuf);
    SHOW_INT(sndbuf);
#if defined(TARGET_LINUX) && HAVE_DECL_SO_MARK
    SHOW_INT(mark);
#endif
    SHOW_INT(sockflags);

    SHOW_BOOL(fast_io);

    SHOW_INT(comp.alg);
    SHOW_INT(comp.flags);

    SHOW_STR(route_script);
    SHOW_STR(route_default_gateway);
    SHOW_INT(route_default_metric);
    SHOW_BOOL(route_noexec);
    SHOW_INT(route_delay);
    SHOW_INT(route_delay_window);
    SHOW_BOOL(route_delay_defined);
    SHOW_BOOL(route_nopull);
    SHOW_BOOL(route_gateway_via_dhcp);
    SHOW_BOOL(allow_pull_fqdn);
    show_pull_filter_list(o->pull_filter_list);

    if (o->routes)
    {
        print_route_options(o->routes, D_SHOW_PARMS);
    }

    if (o->client_nat)
    {
        print_client_nat_list(o->client_nat, D_SHOW_PARMS);
    }

    show_dns_options(&o->dns_options);

#ifdef ENABLE_MANAGEMENT
    SHOW_STR(management_addr);
    SHOW_STR(management_port);
    SHOW_STR(management_user_pass);
    SHOW_INT(management_log_history_cache);
    SHOW_INT(management_echo_buffer_size);
    SHOW_STR(management_client_user);
    SHOW_STR(management_client_group);
    SHOW_INT(management_flags);
#endif
#ifdef ENABLE_PLUGIN
    if (o->plugin_list)
    {
        plugin_option_list_print(o->plugin_list, D_SHOW_PARMS);
    }
#endif

    SHOW_STR_INLINE(shared_secret_file);
    SHOW_PARM(key_direction, keydirection2ascii(o->key_direction, false, true), "%s");
    SHOW_STR(ciphername);
    SHOW_STR(ncp_ciphers);
    SHOW_STR(authname);
#ifndef ENABLE_CRYPTO_MBEDTLS
    SHOW_BOOL(engine);
#endif /* ENABLE_CRYPTO_MBEDTLS */
    SHOW_BOOL(replay);
    SHOW_BOOL(mute_replay_warnings);
    SHOW_INT(replay_window);
    SHOW_INT(replay_time);
    SHOW_STR(packet_id_file);
    SHOW_BOOL(test_crypto);
#ifdef ENABLE_PREDICTION_RESISTANCE
    SHOW_BOOL(use_prediction_resistance);
#endif

    SHOW_BOOL(tls_server);
    SHOW_BOOL(tls_client);
    SHOW_STR_INLINE(ca_file);
    SHOW_STR(ca_path);
    SHOW_STR_INLINE(dh_file);
    if ((o->management_flags & MF_EXTERNAL_CERT))
    {
        SHOW_PARM("cert_file", "EXTERNAL_CERT", "%s");
    }
    else
    {
        SHOW_STR_INLINE(cert_file);
    }
    SHOW_STR_INLINE(extra_certs_file);

    if ((o->management_flags & MF_EXTERNAL_KEY))
    {
        SHOW_PARM("priv_key_file", "EXTERNAL_PRIVATE_KEY", "%s");
    }
    else
    {
        SHOW_STR_INLINE(priv_key_file);
    }
#ifndef ENABLE_CRYPTO_MBEDTLS
    SHOW_STR_INLINE(pkcs12_file);
#endif
#ifdef ENABLE_CRYPTOAPI
    SHOW_STR(cryptoapi_cert);
#endif
    SHOW_STR(cipher_list);
    SHOW_STR(cipher_list_tls13);
    SHOW_STR(tls_cert_profile);
    SHOW_STR(tls_verify);
    SHOW_STR(tls_export_peer_cert_dir);
    SHOW_INT(verify_x509_type);
    SHOW_STR(verify_x509_name);
    SHOW_STR_INLINE(crl_file);
    SHOW_INT(ns_cert_type);
    {
        int i;
        for (i = 0; i<MAX_PARMS; i++)
        {
            SHOW_INT(remote_cert_ku[i]);
        }
    }
    SHOW_STR(remote_cert_eku);
    if (o->verify_hash)
    {
        SHOW_INT(verify_hash_algo);
        SHOW_INT(verify_hash_depth);
        struct gc_arena gc = gc_new();
        struct verify_hash_list *hl = o->verify_hash;
        int digest_len = (o->verify_hash_algo == MD_SHA1) ? SHA_DIGEST_LENGTH :
                         SHA256_DIGEST_LENGTH;
        while (hl)
        {
            char *s = format_hex_ex(hl->hash, digest_len, 0,
                                    1, ":", &gc);
            SHOW_PARM(verify_hash, s, "%s");
            hl = hl->next;
        }
        gc_free(&gc);
    }
    SHOW_INT(ssl_flags);

    SHOW_INT(tls_timeout);

    SHOW_INT(renegotiate_bytes);
    SHOW_INT(renegotiate_packets);
    SHOW_INT(renegotiate_seconds);

    SHOW_INT(handshake_window);
    SHOW_INT(transition_window);

    SHOW_BOOL(single_session);
    SHOW_BOOL(push_peer_info);
    SHOW_BOOL(tls_exit);

    SHOW_STR(tls_crypt_v2_metadata);

#ifdef ENABLE_PKCS11
    {
        int i;
        for (i = 0; i<MAX_PARMS && o->pkcs11_providers[i] != NULL; i++)
        {
            SHOW_PARM(pkcs11_providers, o->pkcs11_providers[i], "%s");
        }
    }
    {
        int i;
        for (i = 0; i<MAX_PARMS; i++)
        {
            SHOW_PARM(pkcs11_protected_authentication, o->pkcs11_protected_authentication[i] ? "ENABLED" : "DISABLED", "%s");
        }
    }
    {
        int i;
        for (i = 0; i<MAX_PARMS; i++)
        {
            SHOW_PARM(pkcs11_private_mode, o->pkcs11_private_mode[i], "%08x");
        }
    }
    {
        int i;
        for (i = 0; i<MAX_PARMS; i++)
        {
            SHOW_PARM(pkcs11_cert_private, o->pkcs11_cert_private[i] ? "ENABLED" : "DISABLED", "%s");
        }
    }
    SHOW_INT(pkcs11_pin_cache_period);
    SHOW_STR(pkcs11_id);
    SHOW_BOOL(pkcs11_id_management);
#endif                  /* ENABLE_PKCS11 */

    show_p2mp_parms(o);

#ifdef _WIN32
    SHOW_BOOL(show_net_up);
    SHOW_INT(route_method);
    SHOW_BOOL(block_outside_dns);
    show_tuntap_options(&o->tuntap_options);
#endif
#endif /* ifndef ENABLE_SMALL */
}

#undef SHOW_PARM
#undef SHOW_STR
#undef SHOW_INT
#undef SHOW_BOOL

#ifdef ENABLE_MANAGEMENT

static struct http_proxy_options *
parse_http_proxy_override(const char *server,
                          const char *port,
                          const char *flags,
                          const int msglevel,
                          struct gc_arena *gc)
{
    if (server && port)
    {
        struct http_proxy_options *ho;
        ALLOC_OBJ_CLEAR_GC(ho, struct http_proxy_options, gc);
        ho->server = string_alloc(server, gc);
        ho->port = port;
        if (flags && !strcmp(flags, "nct"))
        {
            ho->auth_retry = PAR_NCT;
        }
        else
        {
            ho->auth_retry = PAR_ALL;
        }
        ho->http_version = "1.0";
        ho->user_agent = "OpenVPN-Autoproxy/1.0";
        return ho;
    }
    else
    {
        return NULL;
    }
}

static void
options_postprocess_http_proxy_override(struct options *o)
{
    const struct connection_list *l = o->connection_list;
    int i;
    bool succeed = false;
    for (i = 0; i < l->len; ++i)
    {
        struct connection_entry *ce = l->array[i];
        if (ce->proto == PROTO_TCP_CLIENT || ce->proto == PROTO_TCP)
        {
            ce->http_proxy_options = o->http_proxy_override;
            succeed = true;
        }
    }
    if (succeed)
    {
        for (i = 0; i < l->len; ++i)
        {
            struct connection_entry *ce = l->array[i];
            if (ce->proto == PROTO_UDP)
            {
                ce->flags |= CE_DISABLED;
            }
        }
    }
    else
    {
        msg(M_WARN, "Note: option http-proxy-override ignored because no TCP-based connection profiles are defined");
    }
}

#endif /* ifdef ENABLE_MANAGEMENT */

static struct connection_list *
alloc_connection_list_if_undef(struct options *options)
{
    if (!options->connection_list)
    {
        ALLOC_OBJ_CLEAR_GC(options->connection_list, struct connection_list, &options->gc);
    }
    return options->connection_list;
}

static struct connection_entry *
alloc_connection_entry(struct options *options, const int msglevel)
{
    struct connection_list *l = alloc_connection_list_if_undef(options);
    struct connection_entry *e;

    if (l->len == l->capacity)
    {
        int capacity = l->capacity + CONNECTION_LIST_SIZE;
        struct connection_entry **ce = gc_realloc(l->array, capacity*sizeof(struct connection_entry *), &options->gc);
        if (ce == NULL)
        {
            msg(msglevel, "Unable to process more connection options: out of memory. Number of entries = %d", l->len);
            return NULL;
        }
        l->array = ce;
        l->capacity = capacity;
    }
    ALLOC_OBJ_GC(e, struct connection_entry, &options->gc);
    l->array[l->len++] = e;
    return e;
}

static struct remote_list *
alloc_remote_list_if_undef(struct options *options)
{
    if (!options->remote_list)
    {
        ALLOC_OBJ_CLEAR_GC(options->remote_list, struct remote_list, &options->gc);
    }
    return options->remote_list;
}

static struct remote_entry *
alloc_remote_entry(struct options *options, const int msglevel)
{
    struct remote_list *l = alloc_remote_list_if_undef(options);
    struct remote_entry *e;

    if (l->len == l->capacity)
    {
        int capacity = l->capacity + CONNECTION_LIST_SIZE;
        struct remote_entry **re = gc_realloc(l->array, capacity*sizeof(struct remote_entry *), &options->gc);
        if (re == NULL)
        {
            msg(msglevel, "Unable to process more remote options: out of memory. Number of entries = %d", l->len);
            return NULL;
        }
        l->array = re;
        l->capacity = capacity;
    }
    ALLOC_OBJ_GC(e, struct remote_entry, &options->gc);
    l->array[l->len++] = e;
    return e;
}

static struct pull_filter_list *
alloc_pull_filter_list(struct options *o)
{
    if (!o->pull_filter_list)
    {
        ALLOC_OBJ_CLEAR_GC(o->pull_filter_list, struct pull_filter_list, &o->gc);
    }
    return o->pull_filter_list;
}

static struct pull_filter *
alloc_pull_filter(struct options *o, const int msglevel)
{
    struct pull_filter_list *l = alloc_pull_filter_list(o);
    struct pull_filter *f;

    ALLOC_OBJ_CLEAR_GC(f, struct pull_filter, &o->gc);
    if (l->head)
    {
        ASSERT(l->tail);
        l->tail->next = f;
    }
    else
    {
        ASSERT(!l->tail);
        l->head = f;
    }
    l->tail = f;
    return f;
}

static void
connection_entry_load_re(struct connection_entry *ce, const struct remote_entry *re)
{
    if (re->remote)
    {
        ce->remote = re->remote;
    }
    if (re->remote_port)
    {
        ce->remote_port = re->remote_port;
    }
    if (re->proto >= 0)
    {
        ce->proto = re->proto;
    }
    if (re->af > 0)
    {
        ce->af = re->af;
    }
}

static void
connection_entry_preload_key(const char **key_file, bool *key_inline,
                             struct gc_arena *gc)
{
    if (key_file && *key_file && !(*key_inline))
    {
        struct buffer in = buffer_read_from_file(*key_file, gc);
        if (!buf_valid(&in))
        {
            msg(M_FATAL, "Cannot pre-load keyfile (%s)", *key_file);
        }

        *key_file = (const char *) in.data;
        *key_inline = true;
    }
}

static void
check_ca_required(const struct options *options)
{
    if (options->verify_hash_no_ca
        || options->pkcs12_file
        || options->ca_file
#ifndef ENABLE_CRYPTO_MBEDTLS
        || options->ca_path
#endif
        )
    {
        return;
    }

    const char *const str = "You must define CA file (--ca)"
#ifndef ENABLE_CRYPTO_MBEDTLS
                            " or CA path (--capath)"
#endif
                            " and/or peer fingerprint verification (--peer-fingerprint)";
    msg(M_USAGE, "%s", str);
}

static void
options_postprocess_verify_ce(const struct options *options,
                              const struct connection_entry *ce)
{
    struct options defaults;
    int dev = DEV_TYPE_UNDEF;
    bool pull = false;

    init_options(&defaults, true);

    if (options->test_crypto)
    {
        notnull(options->shared_secret_file, "key file (--secret)");
    }
    else
    {
        notnull(options->dev, "TUN/TAP device (--dev)");
    }

    /*
     * Get tun/tap/null device type
     */
    dev = dev_type_enum(options->dev, options->dev_type);

    /*
     * If "proto tcp" is specified, make sure we know whether it is
     * tcp-client or tcp-server.
     */
    if (ce->proto == PROTO_TCP)
    {
        msg(M_USAGE,
            "--proto tcp is ambiguous in this context. Please specify "
            "--proto tcp-server or --proto tcp-client");
    }

    if (options->lladdr && dev != DEV_TYPE_TAP)
    {
        msg(M_USAGE, "--lladdr can only be used in --dev tap mode");
    }

    /*
     * Sanity check on MTU parameters
     */
    if (options->ce.tun_mtu_defined && options->ce.link_mtu_defined)
    {
        msg(M_USAGE, "only one of --tun-mtu or --link-mtu may be defined");
    }

    if (!proto_is_udp(ce->proto) && options->mtu_test)
    {
        msg(M_USAGE, "--mtu-test only makes sense with --proto udp");
    }

    /* will we be pulling options from server? */
    pull = options->pull;

    /*
     * Sanity check on --local, --remote, and --ifconfig
     */

    if (proto_is_net(ce->proto)
        && string_defined_equal(ce->local, ce->remote)
        && string_defined_equal(ce->local_port, ce->remote_port))
    {
        msg(M_USAGE, "--remote and --local addresses are the same");
    }

    if (string_defined_equal(ce->remote, options->ifconfig_local)
        || string_defined_equal(ce->remote, options->ifconfig_remote_netmask))
    {
        msg(M_USAGE,
            "--local and --remote addresses must be distinct from --ifconfig "
            "addresses");
    }

    if (string_defined_equal(ce->local, options->ifconfig_local)
        || string_defined_equal(ce->local, options->ifconfig_remote_netmask))
    {
        msg(M_USAGE,
            "--local addresses must be distinct from --ifconfig addresses");
    }

    if (string_defined_equal(options->ifconfig_local,
                             options->ifconfig_remote_netmask))
    {
        msg(M_USAGE,
            "local and remote/netmask --ifconfig addresses must be different");
    }

    if (ce->bind_defined && !ce->bind_local)
    {
        msg(M_USAGE, "--bind and --nobind can't be used together");
    }

    if (ce->local && !ce->bind_local)
    {
        msg(M_USAGE,
            "--local and --nobind don't make sense when used together");
    }

    if (ce->local_port_defined && !ce->bind_local)
    {
        msg(M_USAGE,
            "--lport and --nobind don't make sense when used together");
    }

    if (!ce->remote && !ce->bind_local)
    {
        msg(M_USAGE, "--nobind doesn't make sense unless used with --remote");
    }

    /*
     * Check for consistency of management options
     */
#ifdef ENABLE_MANAGEMENT
    if (!options->management_addr
        && (options->management_flags
            || options->management_log_history_cache != defaults.management_log_history_cache))
    {
        msg(M_USAGE, "--management is not specified, however one or more options which modify the behavior of --management were specified");
    }

    if ((options->management_client_user || options->management_client_group)
        && !(options->management_flags & MF_UNIX_SOCK))
    {
        msg(M_USAGE, "--management-client-(user|group) can only be used on unix domain sockets");
    }

    if (options->management_addr
        && !(options->management_flags & MF_UNIX_SOCK)
        && (!options->management_user_pass))
    {
        msg(M_WARN, "WARNING: Using --management on a TCP port WITHOUT "
            "passwords is STRONGLY discouraged and considered insecure");
    }

#endif /* ifdef ENABLE_MANAGEMENT */

#if !defined(HAVE_XKEY_PROVIDER)
    if ((tls_version_max() >= TLS_VER_1_3)
        && (options->management_flags & MF_EXTERNAL_KEY)
        && !(options->management_flags & (MF_EXTERNAL_KEY_NOPADDING))
        )
    {
        msg(M_FATAL, "management-external-key with TLS 1.3 or later requires "
            "nopadding argument/support");
    }
#endif
    /*
     * Windows-specific options.
     */

#ifdef _WIN32
    if (dev == DEV_TYPE_TUN && !(pull || (options->ifconfig_local && options->ifconfig_remote_netmask)))
    {
        msg(M_USAGE, "On Windows, --ifconfig is required when --dev tun is used");
    }

    if ((options->tuntap_options.ip_win32_defined)
        && !(pull || (options->ifconfig_local && options->ifconfig_remote_netmask)))
    {
        msg(M_USAGE, "On Windows, --ip-win32 doesn't make sense unless --ifconfig is also used");
    }

    if (options->tuntap_options.dhcp_options & DHCP_OPTIONS_DHCP_REQUIRED)
    {
        const char *prefix = "Some --dhcp-option or --dns options require DHCP server";
        if (options->windows_driver != WINDOWS_DRIVER_TAP_WINDOWS6)
        {
            msg(M_USAGE, "%s, which is not supported by the selected %s driver",
                prefix, print_windows_driver(options->windows_driver));
        }
        else if (options->tuntap_options.ip_win32_type != IPW32_SET_DHCP_MASQ
                 && options->tuntap_options.ip_win32_type != IPW32_SET_ADAPTIVE)
        {
            msg(M_USAGE, "%s, which requires --ip-win32 dynamic or adaptive",
                prefix);
        }
    }

    if (options->windows_driver == WINDOWS_DRIVER_WINTUN && dev != DEV_TYPE_TUN)
    {
        msg(M_USAGE, "--windows-driver wintun requires --dev tun");
    }
#endif /* ifdef _WIN32 */

    /*
     * Check that protocol options make sense.
     */

#ifdef ENABLE_FRAGMENT
    if (!proto_is_udp(ce->proto) && ce->fragment)
    {
        msg(M_USAGE, "--fragment can only be used with --proto udp");
    }
#endif

    if (!ce->remote && ce->proto == PROTO_TCP_CLIENT)
    {
        msg(M_USAGE, "--remote MUST be used in TCP Client mode");
    }

    if ((ce->http_proxy_options) && ce->proto != PROTO_TCP_CLIENT)
    {
        msg(M_USAGE,
            "--http-proxy MUST be used in TCP Client mode (i.e. --proto "
            "tcp-client)");
    }

    if ((ce->http_proxy_options) && !ce->http_proxy_options->server)
    {
        msg(M_USAGE,
            "--http-proxy not specified but other http proxy options present");
    }

    if (ce->http_proxy_options && ce->socks_proxy_server)
    {
        msg(M_USAGE,
            "--http-proxy can not be used together with --socks-proxy");
    }

    if (ce->socks_proxy_server && ce->proto == PROTO_TCP_SERVER)
    {
        msg(M_USAGE, "--socks-proxy can not be used in TCP Server mode");
    }

    if (ce->proto == PROTO_TCP_SERVER && (options->connection_list->len > 1))
    {
        msg(M_USAGE, "TCP server mode allows at most one --remote address");
    }

    /*
     * Check consistency of --mode server options.
     */
    if (options->mode == MODE_SERVER)
    {
#define USAGE_VALID_SERVER_PROTOS "--mode server currently only supports " \
    "--proto values of udp, tcp-server, tcp4-server, or tcp6-server"
#ifdef TARGET_ANDROID
        msg(M_FATAL, "--mode server not supported on Android");
#endif
        if (!(dev == DEV_TYPE_TUN || dev == DEV_TYPE_TAP))
        {
            msg(M_USAGE, "--mode server only works with --dev tun or --dev tap");
        }
        if (options->pull)
        {
            msg(M_USAGE, "--pull cannot be used with --mode server");
        }
        if (options->pull_filter_list)
        {
            msg(M_WARN, "--pull-filter ignored for --mode server");
        }
        if (!(proto_is_udp(ce->proto) || ce->proto == PROTO_TCP_SERVER))
        {
            msg(M_USAGE, USAGE_VALID_SERVER_PROTOS);
        }
#if PORT_SHARE
        if ((options->port_share_host || options->port_share_port)
            && (ce->proto != PROTO_TCP_SERVER))
        {
            msg(M_USAGE, "--port-share only works in TCP server mode "
                "(--proto values of tcp-server, tcp4-server, or tcp6-server)");
        }
#endif
        if (!options->tls_server)
        {
            msg(M_USAGE, "--mode server requires --tls-server");
        }
        if (ce->remote)
        {
            msg(M_USAGE, "--remote cannot be used with --mode server");
        }
        if (!ce->bind_local)
        {
            msg(M_USAGE, "--nobind cannot be used with --mode server");
        }
        if (ce->http_proxy_options)
        {
            msg(M_USAGE, "--http-proxy cannot be used with --mode server");
        }
        if (ce->socks_proxy_server)
        {
            msg(M_USAGE, "--socks-proxy cannot be used with --mode server");
        }
        /* <connection> blocks force to have a remote embedded, so we check
         * for the --remote and bail out if it is present
         */
        if (options->connection_list->len >1
            || options->connection_list->array[0]->remote)
        {
            msg(M_USAGE, "<connection> cannot be used with --mode server");
        }

        if (options->shaper)
        {
            msg(M_USAGE, "--shaper cannot be used with --mode server");
        }
        if (options->ipchange)
        {
            msg(M_USAGE,
                "--ipchange cannot be used with --mode server (use "
                "--client-connect instead)");
        }
        if (!(proto_is_dgram(ce->proto) || ce->proto == PROTO_TCP_SERVER))
        {
            msg(M_USAGE, USAGE_VALID_SERVER_PROTOS);
        }
        if (!proto_is_udp(ce->proto) && (options->cf_max || options->cf_per))
        {
            msg(M_USAGE, "--connect-freq only works with --mode server --proto udp.  Try --max-clients instead.");
        }
        if (!(dev == DEV_TYPE_TAP || (dev == DEV_TYPE_TUN && options->topology == TOP_SUBNET)) && options->ifconfig_pool_netmask)
        {
            msg(M_USAGE, "The third parameter to --ifconfig-pool (netmask) is only valid in --dev tap mode");
        }
        if (options->routes && (options->routes->flags & RG_ENABLE))
        {
            msg(M_USAGE, "--redirect-gateway cannot be used with --mode server (however --push \"redirect-gateway\" is fine)");
        }
        if (options->route_delay_defined)
        {
            msg(M_USAGE, "--route-delay cannot be used with --mode server");
        }
        if (options->up_delay)
        {
            msg(M_USAGE, "--up-delay cannot be used with --mode server");
        }
        if (!options->ifconfig_pool_defined
            && !options->ifconfig_ipv6_pool_defined
            && options->ifconfig_pool_persist_filename)
        {
            msg(M_USAGE,
                "--ifconfig-pool-persist must be used with --ifconfig-pool or --ifconfig-ipv6-pool");
        }
        if (options->ifconfig_ipv6_pool_defined && !options->ifconfig_ipv6_local)
        {
            msg(M_USAGE, "--ifconfig-ipv6-pool needs --ifconfig-ipv6");
        }
        if (options->allow_recursive_routing)
        {
            msg(M_USAGE, "--allow-recursive-routing cannot be used with --mode server");
        }
        if (options->auth_user_pass_file)
        {
            msg(M_USAGE, "--auth-user-pass cannot be used with --mode server (it should be used on the client side only)");
        }
        if (options->ccd_exclusive && !options->client_config_dir)
        {
            msg(M_USAGE, "--ccd-exclusive must be used with --client-config-dir");
        }
        if (options->auth_token_generate && !options->renegotiate_seconds)
        {
            msg(M_USAGE, "--auth-gen-token needs a non-infinite "
                "--renegotiate_seconds setting");
        }
        if (options->auth_token_generate && options->auth_token_renewal
            && options->auth_token_renewal < 2 * options->handshake_window)
        {
            msg(M_USAGE, "--auth-gen-token renewal time needs to be at least "
                " two times --hand-window (%d).",
                options->handshake_window);

        }
        {
            const bool ccnr = (options->auth_user_pass_verify_script
                               || PLUGIN_OPTION_LIST(options)
                               || MAN_CLIENT_AUTH_ENABLED(options));
            const char *postfix = "must be used with --management-client-auth, an --auth-user-pass-verify script, or plugin";
            if ((options->ssl_flags & (SSLF_CLIENT_CERT_NOT_REQUIRED|SSLF_CLIENT_CERT_OPTIONAL)) && !ccnr)
            {
                msg(M_USAGE, "--verify-client-cert none|optional %s", postfix);
            }
            if ((options->ssl_flags & SSLF_USERNAME_AS_COMMON_NAME) && !ccnr)
            {
                msg(M_USAGE, "--username-as-common-name %s", postfix);
            }
            if ((options->ssl_flags & SSLF_AUTH_USER_PASS_OPTIONAL) && !ccnr)
            {
                msg(M_USAGE, "--auth-user-pass-optional %s", postfix);
            }
        }

        if (options->vlan_tagging && dev != DEV_TYPE_TAP)
        {
            msg(M_USAGE, "--vlan-tagging must be used with --dev tap");
        }
        if (!options->vlan_tagging)
        {
            if (options->vlan_accept != defaults.vlan_accept)
            {
                msg(M_USAGE, "--vlan-accept requires --vlan-tagging");
            }
            if (options->vlan_pvid != defaults.vlan_pvid)
            {
                msg(M_USAGE, "--vlan-pvid requires --vlan-tagging");
            }
        }
    }
    else
    {
        /*
         * When not in server mode, err if parameters are
         * specified which require --mode server.
         */
        if (options->ifconfig_pool_defined || options->ifconfig_pool_persist_filename)
        {
            msg(M_USAGE, "--ifconfig-pool/--ifconfig-pool-persist requires --mode server");
        }
        if (options->ifconfig_ipv6_pool_defined)
        {
            msg(M_USAGE, "--ifconfig-ipv6-pool requires --mode server");
        }
        if (options->real_hash_size != defaults.real_hash_size
            || options->virtual_hash_size != defaults.virtual_hash_size)
        {
            msg(M_USAGE, "--hash-size requires --mode server");
        }
        if (options->learn_address_script)
        {
            msg(M_USAGE, "--learn-address requires --mode server");
        }
        if (options->client_connect_script)
        {
            msg(M_USAGE, "--client-connect requires --mode server");
        }
        if (options->client_crresponse_script)
        {
            msg(M_USAGE, "--client-crresponse requires --mode server");
        }
        if (options->client_disconnect_script)
        {
            msg(M_USAGE, "--client-disconnect requires --mode server");
        }
        if (options->client_config_dir || options->ccd_exclusive)
        {
            msg(M_USAGE, "--client-config-dir/--ccd-exclusive requires --mode server");
        }
        if (options->enable_c2c)
        {
            msg(M_USAGE, "--client-to-client requires --mode server");
        }
        if (options->duplicate_cn)
        {
            msg(M_USAGE, "--duplicate-cn requires --mode server");
        }
        if (options->cf_max || options->cf_per)
        {
            msg(M_USAGE, "--connect-freq requires --mode server");
        }
        if (options->ssl_flags & (SSLF_CLIENT_CERT_NOT_REQUIRED|SSLF_CLIENT_CERT_OPTIONAL))
        {
            msg(M_USAGE, "--verify-client-cert requires --mode server");
        }
        if (options->ssl_flags & SSLF_USERNAME_AS_COMMON_NAME)
        {
            msg(M_USAGE, "--username-as-common-name requires --mode server");
        }
        if (options->ssl_flags & SSLF_AUTH_USER_PASS_OPTIONAL)
        {
            msg(M_USAGE, "--auth-user-pass-optional requires --mode server");
        }
        if (options->ssl_flags & SSLF_OPT_VERIFY)
        {
            msg(M_USAGE, "--opt-verify requires --mode server");
        }
        if (options->server_flags & SF_TCP_NODELAY_HELPER)
        {
            msg(M_WARN, "WARNING: setting tcp-nodelay on the client side will not "
                "affect the server. To have TCP_NODELAY in both direction use "
                "tcp-nodelay in the server configuration instead.");
        }
        if (options->auth_user_pass_verify_script)
        {
            msg(M_USAGE, "--auth-user-pass-verify requires --mode server");
        }
        if (options->auth_token_generate)
        {
            msg(M_USAGE, "--auth-gen-token requires --mode server");
        }
#if PORT_SHARE
        if (options->port_share_host || options->port_share_port)
        {
            msg(M_USAGE, "--port-share requires TCP server mode (--mode server --proto tcp-server)");
        }
#endif

        if (options->stale_routes_check_interval)
        {
            msg(M_USAGE, "--stale-routes-check requires --mode server");
        }

        if (options->vlan_tagging)
        {
            msg(M_USAGE, "--vlan-tagging requires --mode server");
        }

        if (options->force_key_material_export)
        {
            msg(M_USAGE, "--force-tls-key-material-export requires --mode server");
        }
    }

    /*
     * Check consistency of replay options
     */
    if (!options->replay
        && (options->replay_window != defaults.replay_window
            || options->replay_time != defaults.replay_time))
    {
        msg(M_USAGE, "--replay-window doesn't make sense when replay protection is disabled with --no-replay");
    }

    /*
     * SSL/TLS mode sanity checks.
     */
    if (options->tls_server + options->tls_client
        +(options->shared_secret_file != NULL) > 1)
    {
        msg(M_USAGE, "specify only one of --tls-server, --tls-client, or --secret");
    }

    if (!options->tls_server && !options->tls_client)
    {
        msg(M_INFO, "DEPRECATION: No tls-client or tls-server option in "
            "configuration detected. OpenVPN 2.7 will remove the "
            "functionality to run a VPN without TLS. "
            "See the examples section in the manual page for "
            "examples of a similar quick setup with peer-fingerprint.");
    }

    if (options->ssl_flags & (SSLF_CLIENT_CERT_NOT_REQUIRED|SSLF_CLIENT_CERT_OPTIONAL))
    {
        msg(M_WARN, "WARNING: POTENTIALLY DANGEROUS OPTION "
            "--verify-client-cert none|optional "
            "may accept clients which do not present a certificate");
    }

    const int tls_version_max =
        (options->ssl_flags >> SSLF_TLS_VERSION_MAX_SHIFT)
        & SSLF_TLS_VERSION_MAX_MASK;
    const int tls_version_min =
        (options->ssl_flags >> SSLF_TLS_VERSION_MIN_SHIFT)
        & SSLF_TLS_VERSION_MIN_MASK;

    if (tls_version_max > 0 && tls_version_max < tls_version_min)
    {
        msg(M_USAGE, "--tls-version-min bigger than --tls-version-max");
    }

    if (options->tls_server || options->tls_client)
    {
        check_ca_required(options);
#ifdef ENABLE_PKCS11
        if (!options->pkcs11_providers[0] && options->pkcs11_id)
        {
            msg(M_WARN, "Option pkcs11-id is ignored as no pkcs11-providers are specified");
        }
        else if (!options->pkcs11_providers[0] && options->pkcs11_id_management)
        {
            msg(M_WARN, "Option pkcs11-id-management is ignored as no pkcs11-providers are specified");
        }

        if (options->pkcs11_providers[0])
        {
            if (options->pkcs11_id_management && options->pkcs11_id != NULL)
            {
                msg(M_USAGE, "Parameter --pkcs11-id cannot be used when --pkcs11-id-management is also specified.");
            }
            if (!options->pkcs11_id_management && options->pkcs11_id == NULL)
            {
                msg(M_USAGE, "Parameter --pkcs11-id or --pkcs11-id-management should be specified.");
            }
            if (options->cert_file)
            {
                msg(M_USAGE, "Parameter --cert cannot be used when --pkcs11-provider is also specified.");
            }
            if (options->priv_key_file)
            {
                msg(M_USAGE, "Parameter --key cannot be used when --pkcs11-provider is also specified.");
            }
            if (options->management_flags & MF_EXTERNAL_KEY)
            {
                msg(M_USAGE, "Parameter --management-external-key cannot be used when --pkcs11-provider is also specified.");
            }
            if (options->management_flags & MF_EXTERNAL_CERT)
            {
                msg(M_USAGE, "Parameter --management-external-cert cannot be used when --pkcs11-provider is also specified.");
            }
            if (options->pkcs12_file)
            {
                msg(M_USAGE, "Parameter --pkcs12 cannot be used when --pkcs11-provider is also specified.");
            }
#ifdef ENABLE_CRYPTOAPI
            if (options->cryptoapi_cert)
            {
                msg(M_USAGE, "Parameter --cryptoapicert cannot be used when --pkcs11-provider is also specified.");
            }
#endif
        }
        else
#endif /* ifdef ENABLE_PKCS11 */
        if ((options->management_flags & MF_EXTERNAL_KEY) && options->priv_key_file)
        {
            msg(M_USAGE, "--key and --management-external-key are mutually exclusive");
        }
        else if ((options->management_flags & MF_EXTERNAL_CERT))
        {
            if (options->cert_file)
            {
                msg(M_USAGE, "--cert and --management-external-cert are mutually exclusive");
            }
            else if (!(options->management_flags & MF_EXTERNAL_KEY))
            {
                msg(M_USAGE, "--management-external-cert must be used with --management-external-key");
            }
        }
        else
#ifdef ENABLE_CRYPTOAPI
        if (options->cryptoapi_cert)
        {
            if (options->cert_file)
            {
                msg(M_USAGE, "Parameter --cert cannot be used when --cryptoapicert is also specified.");
            }
            if (options->priv_key_file)
            {
                msg(M_USAGE, "Parameter --key cannot be used when --cryptoapicert is also specified.");
            }
            if (options->pkcs12_file)
            {
                msg(M_USAGE, "Parameter --pkcs12 cannot be used when --cryptoapicert is also specified.");
            }
            if (options->management_flags & MF_EXTERNAL_KEY)
            {
                msg(M_USAGE, "Parameter --management-external-key cannot be used when --cryptoapicert is also specified.");
            }
            if (options->management_flags & MF_EXTERNAL_CERT)
            {
                msg(M_USAGE, "Parameter --management-external-cert cannot be used when --cryptoapicert is also specified.");
            }
        }
        else
#endif /* ifdef ENABLE_CRYPTOAPI */
        if (options->pkcs12_file)
        {
#ifdef ENABLE_CRYPTO_MBEDTLS
            msg(M_USAGE, "Parameter --pkcs12 cannot be used with the mbed TLS version version of OpenVPN.");
#else
            if (options->ca_path)
            {
                msg(M_USAGE, "Parameter --capath cannot be used when --pkcs12 is also specified.");
            }
            if (options->cert_file)
            {
                msg(M_USAGE, "Parameter --cert cannot be used when --pkcs12 is also specified.");
            }
            if (options->priv_key_file)
            {
                msg(M_USAGE, "Parameter --key cannot be used when --pkcs12 is also specified.");
            }
            if (options->management_flags & MF_EXTERNAL_KEY)
            {
                msg(M_USAGE, "Parameter --management-external-key cannot be used when --pkcs12 is also specified.");
            }
            if (options->management_flags & MF_EXTERNAL_CERT)
            {
                msg(M_USAGE, "Parameter --management-external-cert cannot be used when --pkcs12 is also specified.");
            }
#endif /* ifdef ENABLE_CRYPTO_MBEDTLS */
        }
        else
        {
#ifdef ENABLE_CRYPTO_MBEDTLS
            if (options->ca_path)
            {
                msg(M_USAGE, "Parameter --capath cannot be used with the mbed TLS version version of OpenVPN.");
            }
#endif  /* ifdef ENABLE_CRYPTO_MBEDTLS */
            if (pull)
            {

                const int sum =
                    ((options->cert_file != NULL) || (options->management_flags & MF_EXTERNAL_CERT))
                    + ((options->priv_key_file != NULL) || (options->management_flags & MF_EXTERNAL_KEY));

                if (sum == 0)
                {
                    if (!options->auth_user_pass_file)
                    {
                        msg(M_USAGE, "No client-side authentication method is "
                            "specified.  You must use either "
                            "--cert/--key, --pkcs12, or "
                            "--auth-user-pass");
                    }
                }
                else if (sum != 2)
                {
                    msg(M_USAGE, "If you use one of --cert or --key, you must use them both");
                }
            }
            else
            {
                if (!(options->management_flags & MF_EXTERNAL_CERT))
                {
                    notnull(options->cert_file, "certificate file (--cert) or PKCS#12 file (--pkcs12)");
                }
                if (!(options->management_flags & MF_EXTERNAL_KEY))
                {
                    notnull(options->priv_key_file, "private key file (--key) or PKCS#12 file (--pkcs12)");
                }
            }
        }
        if (ce->tls_auth_file && ce->tls_crypt_file)
        {
            msg(M_USAGE, "--tls-auth and --tls-crypt are mutually exclusive");
        }
        if (options->tls_client && ce->tls_crypt_v2_file
            && (ce->tls_auth_file || ce->tls_crypt_file))
        {
            msg(M_USAGE, "--tls-crypt-v2, --tls-auth and --tls-crypt are mutually exclusive in client mode");
        }
    }
    else
    {
        /*
         * Make sure user doesn't specify any TLS options
         * when in non-TLS mode.
         */

#define MUST_BE_UNDEF(parm) if (options->parm != defaults.parm) {msg(M_USAGE, err, #parm); \
}

        const char err[] = "Parameter %s can only be specified in TLS-mode, i.e. where --tls-server or --tls-client is also specified.";

        MUST_BE_UNDEF(ca_file);
        MUST_BE_UNDEF(ca_path);
        MUST_BE_UNDEF(dh_file);
        MUST_BE_UNDEF(cert_file);
        MUST_BE_UNDEF(priv_key_file);
#ifndef ENABLE_CRYPTO_MBEDTLS
        MUST_BE_UNDEF(pkcs12_file);
#endif
        MUST_BE_UNDEF(cipher_list);
        MUST_BE_UNDEF(cipher_list_tls13);
        MUST_BE_UNDEF(tls_cert_profile);
        MUST_BE_UNDEF(tls_verify);
        MUST_BE_UNDEF(tls_export_peer_cert_dir);
        MUST_BE_UNDEF(verify_x509_name);
        MUST_BE_UNDEF(tls_timeout);
        MUST_BE_UNDEF(renegotiate_bytes);
        MUST_BE_UNDEF(renegotiate_packets);
        MUST_BE_UNDEF(renegotiate_seconds);
        MUST_BE_UNDEF(handshake_window);
        MUST_BE_UNDEF(transition_window);
        MUST_BE_UNDEF(tls_auth_file);
        MUST_BE_UNDEF(tls_crypt_file);
        MUST_BE_UNDEF(tls_crypt_v2_file);
        MUST_BE_UNDEF(single_session);
        MUST_BE_UNDEF(push_peer_info);
        MUST_BE_UNDEF(tls_exit);
        MUST_BE_UNDEF(crl_file);
        MUST_BE_UNDEF(ns_cert_type);
        MUST_BE_UNDEF(remote_cert_ku[0]);
        MUST_BE_UNDEF(remote_cert_eku);
#ifdef ENABLE_PKCS11
        MUST_BE_UNDEF(pkcs11_providers[0]);
        MUST_BE_UNDEF(pkcs11_private_mode[0]);
        MUST_BE_UNDEF(pkcs11_id);
        MUST_BE_UNDEF(pkcs11_id_management);
#endif

        if (pull)
        {
            msg(M_USAGE, err, "--pull");
        }
    }
#undef MUST_BE_UNDEF

    if (options->auth_user_pass_file && !options->pull)
    {
        msg(M_USAGE, "--auth-user-pass requires --pull");
    }

    uninit_options(&defaults);
}

static void
options_postprocess_mutate_ce(struct options *o, struct connection_entry *ce)
{
    const int dev = dev_type_enum(o->dev, o->dev_type);

    if (o->server_defined || o->server_bridge_defined || o->server_bridge_proxy_dhcp)
    {
        if (ce->proto == PROTO_TCP)
        {
            ce->proto = PROTO_TCP_SERVER;
        }
    }

    if (o->client)
    {
        if (ce->proto == PROTO_TCP)
        {
            ce->proto = PROTO_TCP_CLIENT;
        }
    }

    /* an option is present that requires local bind to enabled */
    bool need_bind = ce->local || ce->local_port_defined || ce->bind_defined;

    /* socks proxy is enabled */
    bool uses_socks = ce->proto == PROTO_UDP && ce->socks_proxy_server;

    /* If binding is not forced by an explicit option and we have (at least)
     * one of --tcp-client, --pull (or --client), or socks we do not bind
     * locally to have "normal" IP client behaviour of a random source port */
    if (!need_bind && (ce->proto == PROTO_TCP_CLIENT || uses_socks || o->pull))
    {
        ce->bind_local = false;
    }

    if (!ce->bind_local)
    {
        ce->local_port = NULL;
    }

    /* if protocol forcing is enabled, disable all protocols
     * except for the forced one
     */
    if (o->proto_force >= 0 && o->proto_force != ce->proto)
    {
        ce->flags |= CE_DISABLED;
    }

    if (ce->http_proxy_options)
    {
        ce->http_proxy_options->nocache = ssl_get_auth_nocache();
    }

    /* our socks code is not fully IPv6 enabled yet (TCP works, UDP not)
     * so fall back to IPv4-only (trac #1221)
     */
    if (ce->socks_proxy_server && proto_is_udp(ce->proto) && ce->af != AF_INET)
    {
        if (ce->af == AF_INET6)
        {
            msg(M_INFO, "WARNING: '--proto udp6' is not compatible with "
                "'--socks-proxy' today.  Forcing IPv4 mode." );
        }
        else
        {
            msg(M_INFO, "NOTICE: dual-stack mode for '--proto udp' does not "
                "work correctly with '--socks-proxy' today.  Forcing IPv4." );
        }
        ce->af = AF_INET;
    }

    /*
     * Set MTU defaults
     */
    {
        if (!ce->tun_mtu_defined && !ce->link_mtu_defined)
        {
            ce->tun_mtu_defined = true;
        }
        if ((dev == DEV_TYPE_TAP) && !ce->tun_mtu_extra_defined)
        {
            ce->tun_mtu_extra_defined = true;
            ce->tun_mtu_extra = TAP_MTU_EXTRA_DEFAULT;
        }
    }

    /*
     * If --mssfix is supplied without a parameter or not specified at all,
     * default it to --fragment value, if --fragment is specified and otherwise
     * to the default if tun-mtu is 1500
     */
    if (o->ce.mssfix_default)
    {
#ifdef ENABLE_FRAGMENT
        if (ce->fragment)
        {
            ce->mssfix = ce->fragment;
        }
        else
#endif
        if (ce->tun_mtu_defined)
        {
            if (o->ce.tun_mtu == TUN_MTU_DEFAULT)
            {
                /* We want to only set mssfix default value if we use a default
                 * MTU Size, otherwise the different size of tun should either
                 * already solve the problem or mssfix might artifically make the
                 * payload packets smaller without mssfix 0 */
                ce->mssfix = MSSFIX_DEFAULT;
                ce->mssfix_encap = true;
            }
            else
            {
                /* We still apply the mssfix value but only adjust it to the
                 * size of the tun interface. */
                ce->mssfix = ce->tun_mtu;
                ce->mssfix_fixed = true;
            }
        }
    }

    /*
     * Set per-connection block tls-auth/crypt/crypto-v2 fields if undefined.
     *
     * At the end only one of these will be really set because the parser
     * logic prevents configurations where more are set.
     */
    if (!ce->tls_auth_file && !ce->tls_crypt_file && !ce->tls_crypt_v2_file)
    {
        ce->tls_auth_file = o->tls_auth_file;
        ce->tls_auth_file_inline = o->tls_auth_file_inline;
        ce->key_direction = o->key_direction;

        ce->tls_crypt_file = o->tls_crypt_file;
        ce->tls_crypt_file_inline = o->tls_crypt_file_inline;

        ce->tls_crypt_v2_file = o->tls_crypt_v2_file;
        ce->tls_crypt_v2_file_inline = o->tls_crypt_v2_file_inline;
    }

    /* Pre-cache tls-auth/crypt(-v2) key file if persist-key was specified and
     * keys were not already embedded in the config file.
     */
    if (o->persist_key)
    {
        connection_entry_preload_key(&ce->tls_auth_file,
                                     &ce->tls_auth_file_inline, &o->gc);
        connection_entry_preload_key(&ce->tls_crypt_file,
                                     &ce->tls_crypt_file_inline, &o->gc);
        connection_entry_preload_key(&ce->tls_crypt_v2_file,
                                     &ce->tls_crypt_v2_file_inline, &o->gc);
    }

    if (!proto_is_udp(ce->proto) && ce->explicit_exit_notification)
    {
        msg(M_WARN, "NOTICE: --explicit-exit-notify ignored for --proto tcp");
        ce->explicit_exit_notification = 0;
    }
}

#ifdef _WIN32
/* If iservice is in use, we need def1 method for redirect-gateway */
static void
remap_redirect_gateway_flags(struct options *opt)
{
    if (opt->routes
        && opt->route_method == ROUTE_METHOD_SERVICE
        && opt->routes->flags & RG_REROUTE_GW
        && !(opt->routes->flags & RG_DEF1))
    {
        msg(M_INFO, "Flag 'def1' added to --redirect-gateway (iservice is in use)");
        opt->routes->flags |= RG_DEF1;
    }
}
#endif

/*
 * Save/Restore certain option defaults before --pull is applied.
 */

static void
pre_connect_save(struct options *o)
{
    ALLOC_OBJ_CLEAR_GC(o->pre_connect, struct options_pre_connect, &o->gc);
    o->pre_connect->tuntap_options = o->tuntap_options;
    o->pre_connect->tuntap_options_defined = true;
    o->pre_connect->foreign_option_index = o->foreign_option_index;

    if (o->routes)
    {
        o->pre_connect->routes = clone_route_option_list(o->routes, &o->gc);
        o->pre_connect->routes_defined = true;
    }
    if (o->routes_ipv6)
    {
        o->pre_connect->routes_ipv6 = clone_route_ipv6_option_list(o->routes_ipv6, &o->gc);
        o->pre_connect->routes_ipv6_defined = true;
    }
    if (o->client_nat)
    {
        o->pre_connect->client_nat = clone_client_nat_option_list(o->client_nat, &o->gc);
        o->pre_connect->client_nat_defined = true;
    }

    o->pre_connect->route_default_gateway = o->route_default_gateway;
    o->pre_connect->route_ipv6_default_gateway = o->route_ipv6_default_gateway;

    o->pre_connect->dns_options = clone_dns_options(o->dns_options, &o->gc);

    /* NCP related options that can be overwritten by a push */
    o->pre_connect->ciphername = o->ciphername;
    o->pre_connect->authname = o->authname;

    /* Ping related options should be reset to the config values on reconnect */
    o->pre_connect->ping_rec_timeout = o->ping_rec_timeout;
    o->pre_connect->ping_rec_timeout_action = o->ping_rec_timeout_action;
    o->pre_connect->ping_send_timeout = o->ping_send_timeout;

    /* Miscellaneous Options */
    o->pre_connect->comp = o->comp;
}

void
pre_connect_restore(struct options *o, struct gc_arena *gc)
{
    const struct options_pre_connect *pp = o->pre_connect;
    if (pp)
    {
        CLEAR(o->tuntap_options);
        if (pp->tuntap_options_defined)
        {
            o->tuntap_options = pp->tuntap_options;
        }

        if (pp->routes_defined)
        {
            rol_check_alloc(o);
            copy_route_option_list(o->routes, pp->routes, gc);
        }
        else
        {
            o->routes = NULL;
        }

        if (pp->routes_ipv6_defined)
        {
            rol6_check_alloc(o);
            copy_route_ipv6_option_list(o->routes_ipv6, pp->routes_ipv6, gc);
        }
        else
        {
            o->routes_ipv6 = NULL;
        }

        o->route_default_gateway = pp->route_default_gateway;
        o->route_ipv6_default_gateway = pp->route_ipv6_default_gateway;

        /* Free DNS options and reset them to pre-pull state */
        gc_free(&o->dns_options.gc);
        struct gc_arena dns_gc = gc_new();
        o->dns_options = clone_dns_options(pp->dns_options, &dns_gc);
        o->dns_options.gc = dns_gc;

        if (pp->client_nat_defined)
        {
            cnol_check_alloc(o);
            copy_client_nat_option_list(o->client_nat, pp->client_nat);
        }
        else
        {
            o->client_nat = NULL;
        }

        o->foreign_option_index = pp->foreign_option_index;

        o->ciphername = pp->ciphername;
        o->authname = pp->authname;

        o->ping_rec_timeout = pp->ping_rec_timeout;
        o->ping_rec_timeout_action = pp->ping_rec_timeout_action;
        o->ping_send_timeout = pp->ping_send_timeout;

        /* Miscellaneous Options */
        o->comp = pp->comp;
    }

    o->push_continuation = 0;
    o->push_option_types_found = 0;
    o->imported_protocol_flags = 0;
}

static void
options_postprocess_mutate_invariant(struct options *options)
{
#ifdef _WIN32
    const int dev = dev_type_enum(options->dev, options->dev_type);

    /* when using wintun/ovpn-dco, kernel doesn't send DHCP requests, so don't use it */
    if ((options->windows_driver == WINDOWS_DRIVER_WINTUN
         || options->windows_driver == WINDOWS_DRIVER_DCO)
        && (options->tuntap_options.ip_win32_type == IPW32_SET_DHCP_MASQ
            || options->tuntap_options.ip_win32_type == IPW32_SET_ADAPTIVE))
    {
        options->tuntap_options.ip_win32_type = IPW32_SET_NETSH;
    }

    if ((dev == DEV_TYPE_TUN || dev == DEV_TYPE_TAP) && !options->route_delay_defined)
    {
        /* delay may only be necessary when we perform DHCP handshake */
        const bool dhcp = (options->tuntap_options.ip_win32_type == IPW32_SET_DHCP_MASQ)
                          || (options->tuntap_options.ip_win32_type == IPW32_SET_ADAPTIVE);
        if ((options->mode == MODE_POINT_TO_POINT) && dhcp)
        {
            options->route_delay_defined = true;
            options->route_delay = 5; /* Vista sometimes has a race without this */
        }
    }

    if (options->ifconfig_noexec)
    {
        options->tuntap_options.ip_win32_type = IPW32_SET_MANUAL;
        options->ifconfig_noexec = false;
    }

    remap_redirect_gateway_flags(options);

    /*
     * Check consistency of --mode server options.
     */
    if (options->mode == MODE_SERVER)
    {
        /*
         * We need to explicitly set --tap-sleep because
         * we do not schedule event timers in the top-level context.
         */
        options->tuntap_options.tap_sleep = 10;
        if (options->route_delay_defined && options->route_delay)
        {
            options->tuntap_options.tap_sleep = options->route_delay;
        }
        options->route_delay_defined = false;
    }
#endif /* ifdef _WIN32 */

#ifdef DEFAULT_PKCS11_MODULE
    /* If p11-kit is present on the system then load its p11-kit-proxy.so
     * by default if the user asks for PKCS#11 without otherwise specifying
     * the module to use. */
    if (!options->pkcs11_providers[0]
        && (options->pkcs11_id || options->pkcs11_id_management))
    {
        options->pkcs11_providers[0] = DEFAULT_PKCS11_MODULE;
    }
#endif
}

static void
options_postprocess_verify(const struct options *o)
{
    if (o->connection_list)
    {
        int i;
        for (i = 0; i < o->connection_list->len; ++i)
        {
            options_postprocess_verify_ce(o, o->connection_list->array[i]);
        }
    }
    else
    {
        options_postprocess_verify_ce(o, &o->ce);
    }

    dns_options_verify(M_FATAL, &o->dns_options);

    if (dco_enabled(o) && o->enable_c2c)
    {
        msg(M_WARN, "Note: --client-to-client has no effect when using data "
            "channel offload: packets are always sent to the VPN "
            "interface and then routed based on the system routing table");
    }
}

/**
 * Checks for availibility of Chacha20-Poly1305 and sets
 * the ncp_cipher to either AES-256-GCM:AES-128-GCM or
 * AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305.
 */
static void
options_postprocess_setdefault_ncpciphers(struct options *o)
{
    if (o->ncp_ciphers)
    {
        /* custom --data-ciphers set, keep list */
        return;
    }

    /* check if crypto library supports chacha */
    bool can_do_chacha = cipher_valid("CHACHA20-POLY1305");

    if (can_do_chacha && dco_enabled(o))
    {
        /* also make sure that dco supports chacha */
        can_do_chacha = tls_item_in_cipher_list("CHACHA20-POLY1305", dco_get_supported_ciphers());
    }

    if (can_do_chacha)
    {
        o->ncp_ciphers = "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305";
    }
    else
    {
        o->ncp_ciphers = "AES-256-GCM:AES-128-GCM";
    }
}

static void
options_postprocess_cipher(struct options *o)
{
    if (!o->pull && !(o->mode == MODE_SERVER))
    {
        /* If the cipher is not set, use the old default of BF-CBC. We will
         * warn that this is deprecated on cipher initialisation, no need
         * to warn here as well */
        if (!o->ciphername)
        {
            o->ciphername = "BF-CBC";
        }
        else
        {
            o->enable_ncp_fallback = true;
        }
        return;
    }

    /* pull or P2MP mode */
    if (!o->ciphername)
    {
        /* We still need to set the ciphername to BF-CBC since various other
         * parts of OpenVPN assert that the ciphername is set */
        o->ciphername = "BF-CBC";

        msg(M_INFO, "Note: --cipher is not set. OpenVPN versions before 2.5 "
            "defaulted to BF-CBC as fallback when cipher negotiation "
            "failed in this case. If you need this fallback please add "
            "'--data-ciphers-fallback BF-CBC' to your configuration "
            "and/or add BF-CBC to --data-ciphers.");
    }
    else if (!o->enable_ncp_fallback
             && !tls_item_in_cipher_list(o->ciphername, o->ncp_ciphers))
    {
        msg(M_WARN, "DEPRECATED OPTION: --cipher set to '%s' but missing in "
            "--data-ciphers (%s). OpenVPN ignores --cipher for cipher "
            "negotiations. ",
            o->ciphername, o->ncp_ciphers);
    }
}

/**
 * The option --compat-mode is used to set up default settings to values
 * used on the specified openvpn version and earlier.
 *
 * This function is used in various "default option" paths to test if the
 * user requested compatibility with a version before the one specified
 * as argument. This way some default settings can be automatically
 * altered to guarantee compatibility with the version specified by the
 * user via --compat-mode.
 *
 * @param version   need compatibility with openvpn versions before the
 *                  one specified (20401 = before 2.4.1)
 * @return          whether compatibility should be enabled
 */
static bool
need_compatibility_before(const struct options *o, unsigned int version)
{
    return o->backwards_compatible != 0 && o->backwards_compatible < version;
}

/**
 * Changes default values so that OpenVPN can be compatible with the user
 * specified version
 */
static void
options_set_backwards_compatible_options(struct options *o)
{
    /* TLS min version is not set */
    int tls_ver_min = (o->ssl_flags >> SSLF_TLS_VERSION_MIN_SHIFT)
                      & SSLF_TLS_VERSION_MIN_MASK;
    if (tls_ver_min == 0)
    {
        int tls_ver_max = (o->ssl_flags >> SSLF_TLS_VERSION_MAX_SHIFT)
                          & SSLF_TLS_VERSION_MAX_MASK;
        if (need_compatibility_before(o, 20307))
        {
            /* 2.3.6 and earlier have TLS 1.0 only, set minimum to TLS 1.0 */
            o->ssl_flags |= (TLS_VER_1_0 << SSLF_TLS_VERSION_MIN_SHIFT);
        }
        else if (tls_ver_max == 0 || tls_ver_max >= TLS_VER_1_2)
        {
            /* Use TLS 1.2 as proper default */
            o->ssl_flags |= (TLS_VER_1_2 << SSLF_TLS_VERSION_MIN_SHIFT);
        }
        else
        {
            /* Maximize the minimum version */
            o->ssl_flags |= (tls_ver_max << SSLF_TLS_VERSION_MIN_SHIFT);
        }
    }

    if (need_compatibility_before(o, 20400))
    {
        if (!o->ciphername)
        {
            /* If ciphername is not set default to BF-CBC when targeting these
             * old versions that do not have NCP */
            o->ciphername = "BF-CBC";
        }
        /* Versions < 2.4.0 additionally might be compiled with --enable-small and
         * not have OCC strings required for "poor man's NCP" */
        o->enable_ncp_fallback = true;
    }

    /* Versions < 2.5.0 do need --cipher in the list of accepted ciphers.
     * Version 2.4 probably does not need it but NCP was not so
     * good with 2.4 and ncp-disable might be more common on 2.4 peers.
     * Only do this iff --cipher is set (explicitly or by compat mode
     * < 2.4.0, see above). This is not 100% correct backwards compatible
     * behaviour but 2.5 already behaved like this */
    if (o->ciphername && need_compatibility_before(o, 20500)
        && !tls_item_in_cipher_list(o->ciphername, o->ncp_ciphers))
    {
        append_cipher_to_ncp_list(o, o->ciphername);
    }

#ifdef USE_COMP
    /* Compression is deprecated and we do not want to announce support for it
     * by default anymore, additionally DCO breaks with compression.
     *
     * Disable compression by default starting with 2.6.0 if no other
     * compression related option has been explicitly set */
    if (!need_compatibility_before(o, 20600) && (o->comp.flags == 0))
    {
        if (!comp_non_stub_enabled(&o->comp))
        {
            o->comp.flags = COMP_F_ALLOW_STUB_ONLY | COMP_F_ADVERTISE_STUBS_ONLY;
        }
    }
#else  /* ifdef USE_COMP */
    o->comp.flags = COMP_F_ALLOW_NOCOMP_ONLY;
#endif
}

static void
options_process_mutate_prf(struct options *o)
{
    if (!check_tls_prf_working())
    {
        msg(D_TLS_ERRORS, "Warning: TLS 1.0 PRF with MD5+SHA1 PRF is not "
            "supported by the TLS library. Your system does not support this "
            "calculation anymore or your security policy (e.g. FIPS 140-2) "
            "forbids it. Connections will only work with peers running "
            "OpenVPN 2.6.0 or higher)");
#ifndef HAVE_EXPORT_KEYING_MATERIAL
        msg(M_FATAL, "Keying Material Exporters (RFC 5705) not available either. "
            "No way to generate data channel keys left.");
#endif
        if (o->mode == MODE_SERVER)
        {
            msg(M_WARN, "Automatically enabling option "
                "--force-tls-key-material-export");
            o->force_key_material_export = true;
        }

    }
}

static void
options_postprocess_mutate(struct options *o, struct env_set *es)
{
    int i;
    /*
     * Process helper-type options which map to other, more complex
     * sequences of options.
     */
    helper_client_server(o);
    helper_keepalive(o);
    helper_tcp_nodelay(o);

    options_postprocess_setdefault_ncpciphers(o);
    options_set_backwards_compatible_options(o);
    options_process_mutate_prf(o);

    options_postprocess_cipher(o);
    o->ncp_ciphers = mutate_ncp_cipher_list(o->ncp_ciphers, &o->gc);
    if (o->ncp_ciphers == NULL)
    {
        msg(M_USAGE, "--data-ciphers list contains unsupported ciphers or is too long.");
    }

    if (o->remote_list && !o->connection_list)
    {
        /*
         * Convert remotes into connection list
         */
        const struct remote_list *rl = o->remote_list;
        for (i = 0; i < rl->len; ++i)
        {
            const struct remote_entry *re = rl->array[i];
            struct connection_entry ce = o->ce;
            struct connection_entry *ace;

            ASSERT(re->remote);
            connection_entry_load_re(&ce, re);
            ace = alloc_connection_entry(o, M_USAGE);
            ASSERT(ace);
            *ace = ce;
        }
    }
    else if (!o->remote_list && !o->connection_list)
    {
        struct connection_entry *ace;
        ace = alloc_connection_entry(o, M_USAGE);
        ASSERT(ace);
        *ace = o->ce;
    }

    ASSERT(o->connection_list);
    for (i = 0; i < o->connection_list->len; ++i)
    {
        options_postprocess_mutate_ce(o, o->connection_list->array[i]);
    }

    if (o->tls_server)
    {
        /* Check that DH file is specified, or explicitly disabled */
        notnull(o->dh_file, "DH file (--dh)");
        if (streq(o->dh_file, "none"))
        {
            o->dh_file = NULL;
        }
    }
    else if (o->dh_file)
    {
        /* DH file is only meaningful in a tls-server context. */
        msg(M_WARN, "WARNING: Ignoring option 'dh' in tls-client mode, please only "
            "include this in your server configuration");
        o->dh_file = NULL;
    }
#if ENABLE_MANAGEMENT
    if (o->http_proxy_override)
    {
        options_postprocess_http_proxy_override(o);
    }
#endif
    if (!o->ca_file && !o->ca_path && o->verify_hash
        && o->verify_hash_depth == 0)
    {
        msg(M_INFO, "Using certificate fingerprint to verify peer (no CA "
            "option set). ");
        o->verify_hash_no_ca = true;
    }

    if (o->config && streq(o->config, "stdin") && o->remap_sigusr1 == SIGHUP)
    {
        msg(M_USAGE, "Options 'config stdin' and 'remap-usr1 SIGHUP' are "
            "incompatible with each other.");
    }

    if (dco_enabled(o))
    {
        /* check if any option should force disabling DCO */
        o->tuntap_options.disable_dco = !dco_check_option(D_DCO, o)
                                        || !dco_check_startup_option(D_DCO, o);
    }
#ifdef USE_COMP
    if (dco_enabled(o))
    {
        o->comp.flags |= COMP_F_ALLOW_NOCOMP_ONLY;
    }
#endif

#ifdef _WIN32
    if (dco_enabled(o))
    {
        o->windows_driver = WINDOWS_DRIVER_DCO;
    }
    else
    {
        if (o->windows_driver == WINDOWS_DRIVER_DCO)
        {
            msg(M_WARN, "Option --windows-driver ovpn-dco is ignored because Data Channel Offload is disabled");
            o->windows_driver = WINDOWS_DRIVER_TAP_WINDOWS6;
        }
        else if (o->windows_driver == WINDOWS_DRIVER_UNSPECIFIED)
        {
            o->windows_driver = WINDOWS_DRIVER_TAP_WINDOWS6;
        }
    }
#else  /* _WIN32 */
    if (dco_enabled(o) && o->dev_node)
    {
        msg(M_WARN, "Note: ignoring --dev-node as it has no effect when using "
            "data channel offload");
        o->dev_node = NULL;
    }
#endif /* _WIN32 */

    /* this depends on o->windows_driver, which is set above */
    options_postprocess_mutate_invariant(o);

    /* check that compression settings in the options are okay */
    check_compression_settings_valid(&o->comp, M_USAGE);

    /*
     * Save certain parms before modifying options during connect, especially
     * when using --pull
     */
    if (o->pull)
    {
        dns_options_preprocess_pull(&o->dns_options);
    }
    else
    {
#if defined(_WIN32) || defined(TARGET_ANDROID)
        tuntap_options_copy_dns(o);
#else
        foreign_options_copy_dns(o, es);
#endif
    }
    if (o->auth_token_generate && !o->auth_token_renewal)
    {
        o->auth_token_renewal = o->renegotiate_seconds;
    }
    pre_connect_save(o);
}

/*
 *  Check file/directory sanity
 *
 */
#ifndef ENABLE_SMALL  /** Expect people using the stripped down version to know what they do */

#define CHKACC_FILE (1<<0)       /** Check for a file/directory presence */
#define CHKACC_DIRPATH (1<<1)    /** Check for directory presence where a file should reside */
#define CHKACC_FILEXSTWR (1<<2)  /** If file exists, is it writable? */
#define CHKACC_ACPTSTDIN (1<<3)  /** If filename is stdin, it's allowed and "exists" */
#define CHKACC_PRIVATE (1<<4)    /** Warn if this (private) file is group/others accessible */

static bool
check_file_access(const int type, const char *file, const int mode, const char *opt)
{
    int errcode = 0;

    /* If no file configured, no errors to look for */
    if (!file)
    {
        return false;
    }

    /* If stdin is allowed and the file name is 'stdin', then do no
     * further checks as stdin is always available
     */
    if ( (type & CHKACC_ACPTSTDIN) && streq(file, "stdin") )
    {
        return false;
    }

    /* Is the directory path leading to the given file accessible? */
    if (type & CHKACC_DIRPATH)
    {
        char *fullpath = string_alloc(file, NULL); /* POSIX dirname() implementation may modify its arguments */
        char *dirpath = dirname(fullpath);

        if (platform_access(dirpath, mode|X_OK) != 0)
        {
            errcode = errno;
        }
        free(fullpath);
    }

    /* Is the file itself accessible? */
    if (!errcode && (type & CHKACC_FILE) && (platform_access(file, mode) != 0) )
    {
        errcode = errno;
    }

    /* If the file exists and is accessible, is it writable? */
    if (!errcode && (type & CHKACC_FILEXSTWR) && (platform_access(file, F_OK) == 0) )
    {
        if (platform_access(file, W_OK) != 0)
        {
            errcode = errno;
        }
    }

    /* Warn if a given private file is group/others accessible. */
    if (type & CHKACC_PRIVATE)
    {
        platform_stat_t st;
        if (platform_stat(file, &st))
        {
            msg(M_WARN | M_ERRNO, "WARNING: cannot stat file '%s'", file);
        }
#ifndef _WIN32
        else
        {
            if (st.st_mode & (S_IRWXG|S_IRWXO))
            {
                msg(M_WARN, "WARNING: file '%s' is group or others accessible", file);
            }
        }
#endif
    }

    /* Scream if an error is found */
    if (errcode > 0)
    {
        msg(M_NOPREFIX | M_OPTERR | M_ERRNO, "%s fails with '%s'", opt, file);
    }

    /* Return true if an error occurred */
    return (errcode != 0 ? true : false);
}

/* A wrapper for check_file_access() which also takes a chroot directory.
 * If chroot is NULL, behaviour is exactly the same as calling check_file_access() directly,
 * otherwise it will look for the file inside the given chroot directory instead.
 */
static bool
check_file_access_chroot(const char *chroot, const int type, const char *file, const int mode, const char *opt)
{
    bool ret = false;

    /* If no file configured, no errors to look for */
    if (!file)
    {
        return false;
    }

    /* If chroot is set, look for the file/directory inside the chroot */
    if (chroot)
    {
        struct gc_arena gc = gc_new();
        struct buffer chroot_file;

        chroot_file = prepend_dir(chroot, file, &gc);
        ret = check_file_access(type, BSTR(&chroot_file), mode, opt);
        gc_free(&gc);
    }
    else
    {
        /* No chroot in play, just call core file check function */
        ret = check_file_access(type, file, mode, opt);
    }
    return ret;
}

/**
 * A wrapper for check_file_access_chroot() that returns false immediately if
 * the file is inline (and therefore there is no access to check)
 */
static bool
check_file_access_chroot_inline(bool is_inline, const char *chroot,
                                const int type, const char *file,
                                const int mode, const char *opt)
{
    if (is_inline)
    {
        return false;
    }

    return check_file_access_chroot(chroot, type, file, mode, opt);
}

/**
 * A wrapper for check_file_access() that returns false immediately if the file
 * is inline (and therefore there is no access to check)
 */
static bool
check_file_access_inline(bool is_inline, const int type, const char *file,
                         const int mode, const char *opt)
{
    if (is_inline)
    {
        return false;
    }

    return check_file_access(type, file, mode, opt);
}

/*
 * Verifies that the path in the "command" that comes after certain script options (e.g., --up) is a
 * valid file with appropriate permissions.
 *
 * "command" consists of a path, optionally followed by a space, which may be
 * followed by arbitrary arguments. It is NOT a full shell command line -- shell expansion is not
 * performed.
 *
 * The path and arguments in "command" may be single- or double-quoted or escaped.
 *
 * The path is extracted from "command", then check_file_access() is called to check it. The
 * arguments, if any, are ignored.
 *
 * Note that the type, mode, and opt arguments to this routine are the same as the corresponding
 * check_file_access() arguments.
 */
static bool
check_cmd_access(const char *command, const char *opt, const char *chroot)
{
    struct argv argv;
    bool return_code;

    /* If no command was set, there are no errors to look for */
    if (!command)
    {
        return false;
    }

    /* Extract executable path and arguments */
    argv = argv_new();
    argv_parse_cmd(&argv, command);

    /* if an executable is specified then check it; otherwise, complain */
    if (argv.argv[0])
    {
        /* Scripts requires R_OK as well, but that might fail on binaries which
         * only requires X_OK to function on Unix - a scenario not unlikely to
         * be seen on suid binaries.
         */
        return_code = check_file_access_chroot(chroot, CHKACC_FILE, argv.argv[0], X_OK, opt);
    }
    else
    {
        msg(M_NOPREFIX|M_OPTERR, "%s fails with '%s': No path to executable.",
            opt, command);
        return_code = true;
    }

    argv_free(&argv);

    return return_code;
}

/*
 * Sanity check of all file/dir options.  Checks that file/dir
 * is accessible by OpenVPN
 */
static void
options_postprocess_filechecks(struct options *options)
{
    bool errs = false;

    /* ** SSL/TLS/crypto related files ** */
    errs |= check_file_access_inline(options->dh_file_inline, CHKACC_FILE,
                                     options->dh_file, R_OK, "--dh");

    if (!options->verify_hash_no_ca)
    {
        errs |= check_file_access_inline(options->ca_file_inline, CHKACC_FILE,
                                         options->ca_file, R_OK, "--ca");
    }

    errs |= check_file_access_chroot(options->chroot_dir, CHKACC_FILE,
                                     options->ca_path, R_OK, "--capath");

    errs |= check_file_access_inline(options->cert_file_inline, CHKACC_FILE,
                                     options->cert_file, R_OK, "--cert");

    errs |= check_file_access_inline(options->extra_certs_file, CHKACC_FILE,
                                     options->extra_certs_file, R_OK,
                                     "--extra-certs");

    if (!(options->management_flags & MF_EXTERNAL_KEY))
    {
        errs |= check_file_access_inline(options->priv_key_file_inline,
                                         CHKACC_FILE|CHKACC_PRIVATE,
                                         options->priv_key_file, R_OK, "--key");
    }

    errs |= check_file_access_inline(options->pkcs12_file_inline,
                                     CHKACC_FILE|CHKACC_PRIVATE,
                                     options->pkcs12_file, R_OK, "--pkcs12");

    if (options->ssl_flags & SSLF_CRL_VERIFY_DIR)
    {
        errs |= check_file_access_chroot(options->chroot_dir, CHKACC_FILE,
                                         options->crl_file, R_OK|X_OK,
                                         "--crl-verify directory");
    }
    else
    {
        errs |= check_file_access_chroot_inline(options->crl_file_inline,
                                                options->chroot_dir,
                                                CHKACC_FILE, options->crl_file,
                                                R_OK, "--crl-verify");
    }

    if (options->tls_export_peer_cert_dir)
    {
        errs |= check_file_access_chroot(options->chroot_dir, CHKACC_FILE,
                                         options->tls_export_peer_cert_dir,
                                         W_OK, "--tls-export-cert");
    }

    ASSERT(options->connection_list);
    for (int i = 0; i < options->connection_list->len; ++i)
    {
        struct connection_entry *ce = options->connection_list->array[i];

        errs |= check_file_access_inline(ce->tls_auth_file_inline,
                                         CHKACC_FILE|CHKACC_PRIVATE,
                                         ce->tls_auth_file, R_OK,
                                         "--tls-auth");
        errs |= check_file_access_inline(ce->tls_crypt_file_inline,
                                         CHKACC_FILE|CHKACC_PRIVATE,
                                         ce->tls_crypt_file, R_OK,
                                         "--tls-crypt");
        errs |= check_file_access_inline(ce->tls_crypt_v2_file_inline,
                                         CHKACC_FILE|CHKACC_PRIVATE,
                                         ce->tls_crypt_v2_file, R_OK,
                                         "--tls-crypt-v2");
    }

    errs |= check_file_access_inline(options->shared_secret_file_inline,
                                     CHKACC_FILE|CHKACC_PRIVATE,
                                     options->shared_secret_file, R_OK,
                                     "--secret");

    errs |= check_file_access(CHKACC_DIRPATH|CHKACC_FILEXSTWR,
                              options->packet_id_file, R_OK|W_OK, "--replay-persist");

    /* ** Password files ** */
    errs |= check_file_access(CHKACC_FILE|CHKACC_ACPTSTDIN|CHKACC_PRIVATE,
                              options->key_pass_file, R_OK, "--askpass");
#ifdef ENABLE_MANAGEMENT
    errs |= check_file_access(CHKACC_FILE|CHKACC_ACPTSTDIN|CHKACC_PRIVATE,
                              options->management_user_pass, R_OK,
                              "--management user/password file");
#endif /* ENABLE_MANAGEMENT */
    errs |= check_file_access_inline(options->auth_user_pass_file_inline,
                                     CHKACC_FILE|CHKACC_ACPTSTDIN|CHKACC_PRIVATE,
                                     options->auth_user_pass_file, R_OK,
                                     "--auth-user-pass");
    /* ** System related ** */
    errs |= check_file_access(CHKACC_FILE, options->chroot_dir,
                              R_OK|X_OK, "--chroot directory");
    errs |= check_file_access(CHKACC_DIRPATH|CHKACC_FILEXSTWR, options->writepid,
                              R_OK|W_OK, "--writepid");

    /* ** Log related ** */
    errs |= check_file_access(CHKACC_DIRPATH|CHKACC_FILEXSTWR, options->status_file,
                              R_OK|W_OK, "--status");

    /* ** Config related ** */
    errs |= check_file_access_chroot(options->chroot_dir, CHKACC_FILE, options->client_config_dir,
                                     R_OK|X_OK, "--client-config-dir");
    errs |= check_file_access_chroot(options->chroot_dir, CHKACC_FILE, options->tmp_dir,
                                     R_OK|W_OK|X_OK, "Temporary directory (--tmp-dir)");

    if (errs)
    {
        msg(M_USAGE, "Please correct these errors.");
    }
}
#endif /* !ENABLE_SMALL */

/*
 * Sanity check on options.
 * Also set some options based on other
 * options.
 */
void
options_postprocess(struct options *options, struct env_set *es)
{
    options_postprocess_mutate(options, es);
    options_postprocess_verify(options);
#ifndef ENABLE_SMALL
    options_postprocess_filechecks(options);
#endif /* !ENABLE_SMALL */
}

/*
 * Sanity check on options after more options were pulled from server.
 * Also time to modify some options based on other options.
 */
bool
options_postprocess_pull(struct options *o, struct env_set *es)
{
    bool success = dns_options_verify(D_PUSH_ERRORS, &o->dns_options);
    if (success)
    {
        dns_options_postprocess_pull(&o->dns_options);
        setenv_dns_options(&o->dns_options, es);
#if defined(_WIN32) || defined(TARGET_ANDROID)
        tuntap_options_copy_dns(o);
#else
        foreign_options_copy_dns(o, es);
#endif
    }
    return success;
}

/*
 * Build an options string to represent data channel encryption options.
 * This string must match exactly between peers.  The keysize is checked
 * separately by read_key().
 *
 * The following options must match on both peers:
 *
 * Tunnel options:
 *
 * --dev tun|tap [unit number need not match]
 * --dev-type tun|tap
 * --link-mtu
 * --udp-mtu
 * --tun-mtu
 * --proto udp
 * --proto tcp-client [matched with --proto tcp-server
 *                     on the other end of the connection]
 * --proto tcp-server [matched with --proto tcp-client on
 *                     the other end of the connection]
 * --tun-ipv6
 * --ifconfig x y [matched with --ifconfig y x on
 *                 the other end of the connection]
 *
 * --comp-lzo
 * --compress alg
 * --fragment
 *
 * Crypto Options:
 *
 * --cipher
 * --auth
 * --secret
 * --no-replay
 *
 * SSL Options:
 *
 * --tls-auth
 * --tls-client [matched with --tls-server on
 *               the other end of the connection]
 * --tls-server [matched with --tls-client on
 *               the other end of the connection]
 */
char *
options_string(const struct options *o,
               const struct frame *frame,
               struct tuntap *tt,
               openvpn_net_ctx_t *ctx,
               bool remote,
               struct gc_arena *gc)
{
    struct buffer out = alloc_buf(OPTION_LINE_SIZE);
    bool tt_local = false;

    buf_printf(&out, "V4");

    /*
     * Tunnel Options
     */

    buf_printf(&out, ",dev-type %s", dev_type_string(o->dev, o->dev_type));
    /* the link-mtu that we send has only a meaning if have a fixed
     * cipher (p2p) or have a fallback cipher configured for older non
     * ncp clients. But not sending it will make even 2.4 complain
     * about it being missing. So still send it. */
    buf_printf(&out, ",link-mtu %u",
               (unsigned int) calc_options_string_link_mtu(o, frame));

    if (o->ce.occ_mtu != 0)
    {
        buf_printf(&out, ",tun-mtu %d", o->ce.occ_mtu);
    }
    else
    {
        buf_printf(&out, ",tun-mtu %d", frame->tun_mtu);
    }

    buf_printf(&out, ",proto %s",  proto_remote(o->ce.proto, remote));

    bool p2p_nopull = o->mode == MODE_POINT_TO_POINT && !PULL_DEFINED(o);
    /* send tun_ipv6 only in peer2peer mode - in client/server mode, it
     * is usually pushed by the server, triggering a non-helpful warning
     */
    if (o->ifconfig_ipv6_local && p2p_nopull)
    {
        buf_printf(&out, ",tun-ipv6");
    }

    /*
     * Try to get ifconfig parameters into the options string.
     * If tt is undefined, make a temporary instantiation.
     */
    if (!tt)
    {
        tt = init_tun(o->dev,
                      o->dev_type,
                      o->topology,
                      o->ifconfig_local,
                      o->ifconfig_remote_netmask,
                      o->ifconfig_ipv6_local,
                      o->ifconfig_ipv6_netbits,
                      o->ifconfig_ipv6_remote,
                      NULL,
                      NULL,
                      false,
                      NULL,
                      ctx,
                      NULL);
        if (tt)
        {
            tt_local = true;
        }
    }

    if (tt && p2p_nopull)
    {
        const char *ios = ifconfig_options_string(tt, remote, o->ifconfig_nowarn, gc);
        if (ios && strlen(ios))
        {
            buf_printf(&out, ",ifconfig %s", ios);
        }
    }
    if (tt_local)
    {
        free(tt);
        tt = NULL;
    }

#ifdef USE_COMP
    if (o->comp.alg != COMP_ALG_UNDEF)
    {
        buf_printf(&out, ",comp-lzo"); /* for compatibility, this simply indicates that compression context is active, not necessarily LZO per-se */
    }
#endif

#ifdef ENABLE_FRAGMENT
    if (o->ce.fragment)
    {
        buf_printf(&out, ",mtu-dynamic");
    }
#endif

#define TLS_CLIENT (o->tls_client)
#define TLS_SERVER (o->tls_server)

    /*
     * Key direction
     */
    {
        const char *kd = keydirection2ascii(o->key_direction, remote, false);
        if (kd)
        {
            buf_printf(&out, ",keydir %s", kd);
        }
    }

    /*
     * Crypto Options
     */
    if (o->shared_secret_file || TLS_CLIENT || TLS_SERVER)
    {
        struct key_type kt;

        ASSERT((o->shared_secret_file != NULL)
               + (TLS_CLIENT == true)
               + (TLS_SERVER == true)
               <= 1);

        /* Skip resolving BF-CBC to allow SSL libraries without BF-CBC
         * to work here in the default configuration */
        const char *ciphername = o->ciphername;
        int keysize = 0;

        if (strcmp(o->ciphername, "BF-CBC") == 0)
        {
            init_key_type(&kt, "none", o->authname, true, false);
            keysize = 128;
        }
        else
        {
            init_key_type(&kt, o->ciphername, o->authname, true, false);
            ciphername = cipher_kt_name(kt.cipher);
            if (cipher_defined(o->ciphername))
            {
                keysize = cipher_kt_key_size(kt.cipher) * 8;
            }
        }
        /* Only announce the cipher to our peer if we are willing to
         * support it */
        if (p2p_nopull || tls_item_in_cipher_list(ciphername, o->ncp_ciphers))
        {
            buf_printf(&out, ",cipher %s", ciphername);
        }
        buf_printf(&out, ",auth %s", md_kt_name(kt.digest));
        buf_printf(&out, ",keysize %d", keysize);
        if (o->shared_secret_file)
        {
            buf_printf(&out, ",secret");
        }
        if (!o->replay)
        {
            buf_printf(&out, ",no-replay");
        }

#ifdef ENABLE_PREDICTION_RESISTANCE
        if (o->use_prediction_resistance)
        {
            buf_printf(&out, ",use-prediction-resistance");
        }
#endif
    }

    /*
     * SSL Options
     */
    {
        if (TLS_CLIENT || TLS_SERVER)
        {
            if (o->ce.tls_auth_file)
            {
                buf_printf(&out, ",tls-auth");
            }
            /* Not adding tls-crypt here, because we won't reach this code if
             * tls-auth/tls-crypt does not match.  Removing tls-auth here would
             * break stuff, so leaving that in place. */

            buf_printf(&out, ",key-method %d", KEY_METHOD_2);
        }

        if (remote)
        {
            if (TLS_CLIENT)
            {
                buf_printf(&out, ",tls-server");
            }
            else if (TLS_SERVER)
            {
                buf_printf(&out, ",tls-client");
            }
        }
        else
        {
            if (TLS_CLIENT)
            {
                buf_printf(&out, ",tls-client");
            }
            else if (TLS_SERVER)
            {
                buf_printf(&out, ",tls-server");
            }
        }
    }

#undef TLS_CLIENT
#undef TLS_SERVER

    return BSTR(&out);
}

/*
 * Compare option strings for equality.
 * If the first two chars of the strings differ, it means that
 * we are looking at different versions of the options string,
 * therefore don't compare them and return true.
 */

bool
options_cmp_equal(char *actual, const char *expected)
{
    return options_cmp_equal_safe(actual, expected, strlen(actual) + 1);
}

void
options_warning(char *actual, const char *expected)
{
    options_warning_safe(actual, expected, strlen(actual) + 1);
}

static const char *
options_warning_extract_parm1(const char *option_string,
                              struct gc_arena *gc_ret)
{
    struct gc_arena gc = gc_new();
    struct buffer b = string_alloc_buf(option_string, &gc);
    char *p = gc_malloc(OPTION_PARM_SIZE, false, &gc);
    const char *ret;

    buf_parse(&b, ' ', p, OPTION_PARM_SIZE);
    ret = string_alloc(p, gc_ret);
    gc_free(&gc);
    return ret;
}

static void
options_warning_safe_scan2(const int msglevel,
                           const int delim,
                           const bool report_inconsistent,
                           const char *p1,
                           const struct buffer *b2_src,
                           const char *b1_name,
                           const char *b2_name)
{
    /* We will stop sending 'key-method', 'keydir', 'proto' and 'tls-auth' in
     * OCC in a future version (because it's not useful). To reduce questions
     * when interoperating, we no longer printing a warning about it.
     */
    if (strprefix(p1, "key-method ")
        || strprefix(p1, "keydir ")
        || strprefix(p1, "proto ")
        || streq(p1, "tls-auth")
        || strprefix(p1, "tun-ipv6")
        || strprefix(p1, "cipher "))
    {
        return;
    }

    if (strlen(p1) > 0)
    {
        struct gc_arena gc = gc_new();
        struct buffer b2 = *b2_src;
        const char *p1_prefix = options_warning_extract_parm1(p1, &gc);
        char *p2 = gc_malloc(OPTION_PARM_SIZE, false, &gc);

        while (buf_parse(&b2, delim, p2, OPTION_PARM_SIZE))
        {
            if (strlen(p2))
            {
                const char *p2_prefix = options_warning_extract_parm1(p2, &gc);

                if (!strcmp(p1, p2))
                {
                    goto done;
                }
                if (!strcmp(p1_prefix, p2_prefix))
                {
                    if (report_inconsistent)
                    {
                        msg(msglevel, "WARNING: '%s' is used inconsistently, %s='%s', %s='%s'",
                            safe_print(p1_prefix, &gc),
                            b1_name,
                            safe_print(p1, &gc),
                            b2_name,
                            safe_print(p2, &gc));
                    }
                    goto done;
                }
            }
        }

        msg(msglevel, "WARNING: '%s' is present in %s config but missing in %s config, %s='%s'",
            safe_print(p1_prefix, &gc),
            b1_name,
            b2_name,
            b1_name,
            safe_print(p1, &gc));

done:
        gc_free(&gc);
    }
}

static void
options_warning_safe_scan1(const int msglevel,
                           const int delim,
                           const bool report_inconsistent,
                           const struct buffer *b1_src,
                           const struct buffer *b2_src,
                           const char *b1_name,
                           const char *b2_name)
{
    struct gc_arena gc = gc_new();
    struct buffer b = *b1_src;
    char *p = gc_malloc(OPTION_PARM_SIZE, true, &gc);

    while (buf_parse(&b, delim, p, OPTION_PARM_SIZE))
    {
        options_warning_safe_scan2(msglevel, delim, report_inconsistent, p, b2_src, b1_name, b2_name);
    }

    gc_free(&gc);
}

static void
options_warning_safe_ml(const int msglevel, char *actual, const char *expected, size_t actual_n)
{
    struct gc_arena gc = gc_new();

    if (actual_n > 0)
    {
        struct buffer local = alloc_buf_gc(OPTION_PARM_SIZE + 16, &gc);
        struct buffer remote = alloc_buf_gc(OPTION_PARM_SIZE + 16, &gc);
        actual[actual_n - 1] = 0;

        buf_printf(&local, "version %s", expected);
        buf_printf(&remote, "version %s", actual);

        options_warning_safe_scan1(msglevel, ',', true,
                                   &local, &remote,
                                   "local", "remote");

        options_warning_safe_scan1(msglevel, ',', false,
                                   &remote, &local,
                                   "remote", "local");
    }

    gc_free(&gc);
}

bool
options_cmp_equal_safe(char *actual, const char *expected, size_t actual_n)
{
    struct gc_arena gc = gc_new();
    bool ret = true;

    if (actual_n > 0)
    {
        actual[actual_n - 1] = 0;
        if (strncmp(actual, expected, 2))
        {
            msg(D_SHOW_OCC, "NOTE: Options consistency check may be skewed by version differences");
            options_warning_safe_ml(D_SHOW_OCC, actual, expected, actual_n);
        }
        else
        {
            ret = !strcmp(actual, expected);
        }
    }
    gc_free(&gc);
    return ret;
}

void
options_warning_safe(char *actual, const char *expected, size_t actual_n)
{
    options_warning_safe_ml(D_SHOW_OCC, actual, expected, actual_n);
}

const char *
options_string_version(const char *s, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(4, gc);
    strncpynt((char *) BPTR(&out), s, 3);
    return BSTR(&out);
}

char *
options_string_extract_option(const char *options_string, const char *opt_name,
                              struct gc_arena *gc)
{
    char *ret = NULL;
    const size_t opt_name_len = strlen(opt_name);

    const char *p = options_string;
    while (p)
    {
        if (0 == strncmp(p, opt_name, opt_name_len)
            && strlen(p) > (opt_name_len+1) && p[opt_name_len] == ' ')
        {
            /* option found, extract value */
            const char *start = &p[opt_name_len+1];
            const char *end = strchr(p, ',');
            size_t val_len = end ? end - start : strlen(start);
            ret = gc_malloc(val_len+1, true, gc);
            memcpy(ret, start, val_len);
            break;
        }
        p = strchr(p, ',');
        if (p)
        {
            p++; /* skip delimiter */
        }
    }
    return ret;
}

#ifdef _WIN32
/**
 * Parses --windows-driver config option
 *
 * @param str       value of --windows-driver option
 * @param msglevel  msglevel to report parsing error
 * @return enum windows_driver_type  driver type, WINDOWS_DRIVER_UNSPECIFIED on unknown --windows-driver value
 */
static enum windows_driver_type
parse_windows_driver(const char *str, const int msglevel)
{
    if (streq(str, "tap-windows6"))
    {
        return WINDOWS_DRIVER_TAP_WINDOWS6;
    }
    else if (streq(str, "wintun"))
    {
        return WINDOWS_DRIVER_WINTUN;
    }

    else if (streq(str, "ovpn-dco"))
    {
        return WINDOWS_DRIVER_DCO;
    }
    else
    {
        msg(msglevel, "--windows-driver must be tap-windows6, wintun "
            "or ovpn-dco");
        return WINDOWS_DRIVER_UNSPECIFIED;
    }
}
#endif /* ifdef _WIN32 */

/*
 * parse/print topology coding
 */

int
parse_topology(const char *str, const int msglevel)
{
    if (streq(str, "net30"))
    {
        return TOP_NET30;
    }
    else if (streq(str, "p2p"))
    {
        return TOP_P2P;
    }
    else if (streq(str, "subnet"))
    {
        return TOP_SUBNET;
    }
    else
    {
        msg(msglevel, "--topology must be net30, p2p, or subnet");
        return TOP_UNDEF;
    }
}

const char *
print_topology(const int topology)
{
    switch (topology)
    {
        case TOP_UNDEF:
            return "undef";

        case TOP_NET30:
            return "net30";

        case TOP_P2P:
            return "p2p";

        case TOP_SUBNET:
            return "subnet";

        default:
            return "unknown";
    }
}

/*
 * Manage auth-retry variable
 */

static int global_auth_retry; /* GLOBAL */

int
auth_retry_get(void)
{
    return global_auth_retry;
}

bool
auth_retry_set(const int msglevel, const char *option)
{
    if (streq(option, "interact"))
    {
        global_auth_retry = AR_INTERACT;
    }
    else if (streq(option, "nointeract"))
    {
        global_auth_retry = AR_NOINTERACT;
    }
    else if (streq(option, "none"))
    {
        global_auth_retry = AR_NONE;
    }
    else
    {
        msg(msglevel, "--auth-retry method must be 'interact', 'nointeract', or 'none'");
        return false;
    }
    return true;
}

const char *
auth_retry_print(void)
{
    switch (global_auth_retry)
    {
        case AR_NONE:
            return "none";

        case AR_NOINTERACT:
            return "nointeract";

        case AR_INTERACT:
            return "interact";

        default:
            return "???";
    }
}

/*
 * Print the help message.
 */
static void
usage(void)
{
    FILE *fp = msg_fp(0);

#ifdef ENABLE_SMALL

    fprintf(fp, "Usage message not available\n");

#else

    struct options o;
    init_options(&o, true);

    fprintf(fp, usage_message,
            title_string,
            o.ce.connect_retry_seconds,
            o.ce.connect_retry_seconds_max,
            o.ce.local_port, o.ce.remote_port,
            TUN_MTU_DEFAULT, TAP_MTU_EXTRA_DEFAULT,
            o.verbosity,
            o.authname,
            o.replay_window, o.replay_time,
            o.tls_timeout, o.renegotiate_seconds,
            o.handshake_window, o.transition_window);
    fflush(fp);

#endif /* ENABLE_SMALL */

    openvpn_exit(OPENVPN_EXIT_STATUS_USAGE); /* exit point */
}

void
usage_small(void)
{
    msg(M_WARN|M_NOPREFIX, "Use --help for more information.");
    openvpn_exit(OPENVPN_EXIT_STATUS_USAGE); /* exit point */
}

#ifdef _WIN32
void
show_windows_version(const unsigned int flags)
{
    struct gc_arena gc = gc_new();
    msg(flags, "Windows version %s", win32_version_string(&gc, true));
    gc_free(&gc);
}
#endif

void
show_dco_version(const unsigned int flags)
{
#ifdef ENABLE_DCO
    struct gc_arena gc = gc_new();
    msg(flags, "DCO version: %s", dco_version_string(&gc));
    gc_free(&gc);
#endif
}

void
show_library_versions(const unsigned int flags)
{
#ifdef ENABLE_LZO
#define LZO_LIB_VER_STR ", LZO ", lzo_version_string()
#else
#define LZO_LIB_VER_STR "", ""
#endif

    msg(flags, "library versions: %s%s%s", get_ssl_library_version(),
        LZO_LIB_VER_STR);

#undef LZO_LIB_VER_STR
}

static void
usage_version(void)
{
    msg(M_INFO|M_NOPREFIX, "%s", title_string);
    show_library_versions( M_INFO|M_NOPREFIX );
#ifdef _WIN32
    show_windows_version( M_INFO|M_NOPREFIX );
#endif
    show_dco_version(M_INFO | M_NOPREFIX);
    msg(M_INFO|M_NOPREFIX, "Originally developed by James Yonan");
    msg(M_INFO|M_NOPREFIX, "Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>");
#ifndef ENABLE_SMALL
#ifdef CONFIGURE_DEFINES
    msg(M_INFO|M_NOPREFIX, "Compile time defines: %s", CONFIGURE_DEFINES);
#endif
#ifdef CONFIGURE_SPECIAL_BUILD
    msg(M_INFO|M_NOPREFIX, "special build: %s", CONFIGURE_SPECIAL_BUILD);
#endif
#endif
    openvpn_exit(OPENVPN_EXIT_STATUS_GOOD);
}

void
notnull(const char *arg, const char *description)
{
    if (!arg)
    {
        msg(M_USAGE, "You must define %s", description);
    }
}

bool
string_defined_equal(const char *s1, const char *s2)
{
    if (s1 && s2)
    {
        return !strcmp(s1, s2);
    }
    else
    {
        return false;
    }
}

#if 0
static void
ping_rec_err(int msglevel)
{
    msg(msglevel, "only one of --ping-exit or --ping-restart options may be specified");
}
#endif

static int
positive_atoi(const char *str)
{
    const int i = atoi(str);
    return i < 0 ? 0 : i;
}

#ifdef _WIN32  /* This function is only used when compiling on Windows */
static unsigned int
atou(const char *str)
{
    unsigned int val = 0;
    sscanf(str, "%u", &val);
    return val;
}
#endif

static inline bool
space(unsigned char c)
{
    return c == '\0' || isspace(c);
}

int
parse_line(const char *line,
           char *p[],
           const int n,
           const char *file,
           const int line_num,
           int msglevel,
           struct gc_arena *gc)
{
    const int STATE_INITIAL = 0;
    const int STATE_READING_QUOTED_PARM = 1;
    const int STATE_READING_UNQUOTED_PARM = 2;
    const int STATE_DONE = 3;
    const int STATE_READING_SQUOTED_PARM = 4;

    const char *error_prefix = "";

    int ret = 0;
    const char *c = line;
    int state = STATE_INITIAL;
    bool backslash = false;
    char in, out;

    char parm[OPTION_PARM_SIZE];
    unsigned int parm_len = 0;

    msglevel &= ~M_OPTERR;

    if (msglevel & M_MSG_VIRT_OUT)
    {
        error_prefix = "ERROR: ";
    }

    do
    {
        in = *c;
        out = 0;

        if (!backslash && in == '\\' && state != STATE_READING_SQUOTED_PARM)
        {
            backslash = true;
        }
        else
        {
            if (state == STATE_INITIAL)
            {
                if (!space(in))
                {
                    if (in == ';' || in == '#') /* comment */
                    {
                        break;
                    }
                    if (!backslash && in == '\"')
                    {
                        state = STATE_READING_QUOTED_PARM;
                    }
                    else if (!backslash && in == '\'')
                    {
                        state = STATE_READING_SQUOTED_PARM;
                    }
                    else
                    {
                        out = in;
                        state = STATE_READING_UNQUOTED_PARM;
                    }
                }
            }
            else if (state == STATE_READING_UNQUOTED_PARM)
            {
                if (!backslash && space(in))
                {
                    state = STATE_DONE;
                }
                else
                {
                    out = in;
                }
            }
            else if (state == STATE_READING_QUOTED_PARM)
            {
                if (!backslash && in == '\"')
                {
                    state = STATE_DONE;
                }
                else
                {
                    out = in;
                }
            }
            else if (state == STATE_READING_SQUOTED_PARM)
            {
                if (in == '\'')
                {
                    state = STATE_DONE;
                }
                else
                {
                    out = in;
                }
            }
            if (state == STATE_DONE)
            {
                /* ASSERT (parm_len > 0); */
                p[ret] = gc_malloc(parm_len + 1, true, gc);
                memcpy(p[ret], parm, parm_len);
                p[ret][parm_len] = '\0';
                state = STATE_INITIAL;
                parm_len = 0;
                ++ret;
            }

            if (backslash && out)
            {
                if (!(out == '\\' || out == '\"' || space(out)))
                {
#ifdef ENABLE_SMALL
                    msg(msglevel, "%sOptions warning: Bad backslash ('\\') usage in %s:%d", error_prefix, file, line_num);
#else
                    msg(msglevel, "%sOptions warning: Bad backslash ('\\') usage in %s:%d: remember that backslashes are treated as shell-escapes and if you need to pass backslash characters as part of a Windows filename, you should use double backslashes such as \"c:\\\\" PACKAGE "\\\\static.key\"", error_prefix, file, line_num);
#endif
                    return 0;
                }
            }
            backslash = false;
        }

        /* store parameter character */
        if (out)
        {
            if (parm_len >= SIZE(parm))
            {
                parm[SIZE(parm) - 1] = 0;
                msg(msglevel, "%sOptions error: Parameter at %s:%d is too long (%d chars max): %s",
                    error_prefix, file, line_num, (int) SIZE(parm), parm);
                return 0;
            }
            parm[parm_len++] = out;
        }

        /* avoid overflow if too many parms in one config file line */
        if (ret >= n)
        {
            break;
        }

    } while (*c++ != '\0');

    if (state == STATE_READING_QUOTED_PARM)
    {
        msg(msglevel, "%sOptions error: No closing quotation (\") in %s:%d", error_prefix, file, line_num);
        return 0;
    }
    if (state == STATE_READING_SQUOTED_PARM)
    {
        msg(msglevel, "%sOptions error: No closing single quotation (\') in %s:%d", error_prefix, file, line_num);
        return 0;
    }
    if (state != STATE_INITIAL)
    {
        msg(msglevel, "%sOptions error: Residual parse state (%d) in %s:%d", error_prefix, state, file, line_num);
        return 0;
    }
#if 0
    {
        int i;
        for (i = 0; i < ret; ++i)
        {
            msg(M_INFO|M_NOPREFIX, "%s:%d ARG[%d] '%s'", file, line_num, i, p[i]);
        }
    }
#endif
    return ret;
}

static void
bypass_doubledash(char **p)
{
    if (strlen(*p) >= 3 && !strncmp(*p, "--", 2))
    {
        *p += 2;
    }
}

struct in_src {
#define IS_TYPE_FP 1
#define IS_TYPE_BUF 2
    int type;
    union {
        FILE *fp;
        struct buffer *multiline;
    } u;
};

static bool
in_src_get(const struct in_src *is, char *line, const int size)
{
    if (is->type == IS_TYPE_FP)
    {
        return BOOL_CAST(fgets(line, size, is->u.fp));
    }
    else if (is->type == IS_TYPE_BUF)
    {
        bool status = buf_parse(is->u.multiline, '\n', line, size);
        if ((int) strlen(line) + 1 < size)
        {
            strcat(line, "\n");
        }
        return status;
    }
    else
    {
        ASSERT(0);
        return false;
    }
}

static char *
read_inline_file(struct in_src *is, const char *close_tag,
                 int *num_lines, struct gc_arena *gc)
{
    char line[OPTION_LINE_SIZE];
    struct buffer buf = alloc_buf(8*OPTION_LINE_SIZE);
    char *ret;
    bool endtagfound = false;

    while (in_src_get(is, line, sizeof(line)))
    {
        (*num_lines)++;
        char *line_ptr = line;
        /* Remove leading spaces */
        while (isspace(*line_ptr))
        {
            line_ptr++;
        }
        if (!strncmp(line_ptr, close_tag, strlen(close_tag)))
        {
            endtagfound = true;
            break;
        }
        if (!buf_safe(&buf, strlen(line)+1))
        {
            /* Increase buffer size */
            struct buffer buf2 = alloc_buf(buf.capacity * 2);
            ASSERT(buf_copy(&buf2, &buf));
            buf_clear(&buf);
            free_buf(&buf);
            buf = buf2;
        }
        buf_printf(&buf, "%s", line);
    }
    if (!endtagfound)
    {
        msg(M_FATAL, "ERROR: Endtag %s missing", close_tag);
    }
    ret = string_alloc(BSTR(&buf), gc);
    buf_clear(&buf);
    free_buf(&buf);
    secure_memzero(line, sizeof(line));
    return ret;
}

static int
check_inline_file(struct in_src *is, char *p[], struct gc_arena *gc)
{
    int num_inline_lines = 0;

    if (p[0] && !p[1])
    {
        char *arg = p[0];
        if (arg[0] == '<' && arg[strlen(arg)-1] == '>')
        {
            struct buffer close_tag;

            arg[strlen(arg) - 1] = '\0';
            p[0] = string_alloc(arg + 1, gc);
            close_tag = alloc_buf(strlen(p[0]) + 4);
            buf_printf(&close_tag, "</%s>", p[0]);
            p[1] = read_inline_file(is, BSTR(&close_tag), &num_inline_lines, gc);
            p[2] = NULL;
            free_buf(&close_tag);
        }
    }
    return num_inline_lines;
}

static int
check_inline_file_via_fp(FILE *fp, char *p[], struct gc_arena *gc)
{
    struct in_src is;
    is.type = IS_TYPE_FP;
    is.u.fp = fp;
    return check_inline_file(&is, p, gc);
}

static int
check_inline_file_via_buf(struct buffer *multiline, char *p[],
                          struct gc_arena *gc)
{
    struct in_src is;
    is.type = IS_TYPE_BUF;
    is.u.multiline = multiline;
    return check_inline_file(&is, p, gc);
}

static void
add_option(struct options *options,
           char *p[],
           bool is_inline,
           const char *file,
           int line,
           const int level,
           const int msglevel,
           const unsigned int permission_mask,
           unsigned int *option_types_found,
           struct env_set *es);

static void
read_config_file(struct options *options,
                 const char *file,
                 int level,
                 const char *top_file,
                 const int top_line,
                 const int msglevel,
                 const unsigned int permission_mask,
                 unsigned int *option_types_found,
                 struct env_set *es)
{
    const int max_recursive_levels = 10;
    FILE *fp;
    int line_num;
    char line[OPTION_LINE_SIZE+1];
    char *p[MAX_PARMS+1];

    ++level;
    if (level <= max_recursive_levels)
    {
        if (streq(file, "stdin"))
        {
            fp = stdin;
        }
        else
        {
            fp = platform_fopen(file, "r");
        }
        if (fp)
        {
            line_num = 0;
            while (fgets(line, sizeof(line), fp))
            {
                int offset = 0;
                CLEAR(p);
                ++line_num;
                if (strlen(line) == OPTION_LINE_SIZE)
                {
                    msg(msglevel, "In %s:%d: Maximum option line length (%d) exceeded, line starts with %s",
                        file, line_num, OPTION_LINE_SIZE, line);
                }

                /* Ignore UTF-8 BOM at start of stream */
                if (line_num == 1 && strncmp(line, "\xEF\xBB\xBF", 3) == 0)
                {
                    offset = 3;
                }
                if (parse_line(line + offset, p, SIZE(p)-1, file, line_num, msglevel, &options->gc))
                {
                    bypass_doubledash(&p[0]);
                    int lines_inline = check_inline_file_via_fp(fp, p, &options->gc);
                    add_option(options, p, lines_inline, file, line_num, level,
                               msglevel, permission_mask, option_types_found,
                               es);
                    line_num += lines_inline;
                }
            }
            if (fp != stdin)
            {
                fclose(fp);
            }
        }
        else
        {
            msg(msglevel, "In %s:%d: Error opening configuration file: %s", top_file, top_line, file);
        }
    }
    else
    {
        msg(msglevel, "In %s:%d: Maximum recursive include levels exceeded in include attempt of file %s -- probably you have a configuration file that tries to include itself.", top_file, top_line, file);
    }
    secure_memzero(line, sizeof(line));
    CLEAR(p);
}

static void
read_config_string(const char *prefix,
                   struct options *options,
                   const char *config,
                   const int msglevel,
                   const unsigned int permission_mask,
                   unsigned int *option_types_found,
                   struct env_set *es)
{
    char line[OPTION_LINE_SIZE];
    struct buffer multiline;
    int line_num = 0;

    buf_set_read(&multiline, (uint8_t *)config, strlen(config));

    while (buf_parse(&multiline, '\n', line, sizeof(line)))
    {
        char *p[MAX_PARMS+1];
        CLEAR(p);
        ++line_num;
        if (parse_line(line, p, SIZE(p)-1, prefix, line_num, msglevel, &options->gc))
        {
            bypass_doubledash(&p[0]);
            int lines_inline = check_inline_file_via_buf(&multiline, p, &options->gc);
            add_option(options, p, lines_inline, prefix, line_num, 0, msglevel,
                       permission_mask, option_types_found, es);
            line_num += lines_inline;
        }
        CLEAR(p);
    }
    secure_memzero(line, sizeof(line));
}

void
parse_argv(struct options *options,
           const int argc,
           char *argv[],
           const int msglevel,
           const unsigned int permission_mask,
           unsigned int *option_types_found,
           struct env_set *es)
{
    /* usage message */
    if (argc <= 1)
    {
        usage();
    }

    /* config filename specified only? */
    if (argc == 2 && strncmp(argv[1], "--", 2))
    {
        char *p[MAX_PARMS+1];
        CLEAR(p);
        p[0] = "config";
        p[1] = argv[1];
        add_option(options, p, false, NULL, 0, 0, msglevel, permission_mask,
                   option_types_found, es);
    }
    else
    {
        /* parse command line */
        for (int i = 1; i < argc; ++i)
        {
            char *p[MAX_PARMS+1];
            CLEAR(p);
            p[0] = argv[i];
            if (strncmp(p[0], "--", 2))
            {
                msg(msglevel, "I'm trying to parse \"%s\" as an --option parameter but I don't see a leading '--'", p[0]);
            }
            else
            {
                p[0] += 2;
            }

            int j;
            for (j = 1; j < MAX_PARMS; ++j)
            {
                if (i + j < argc)
                {
                    char *arg = argv[i + j];
                    if (strncmp(arg, "--", 2))
                    {
                        p[j] = arg;
                    }
                    else
                    {
                        break;
                    }
                }
            }
            add_option(options, p, false, NULL, 0, 0, msglevel, permission_mask,
                       option_types_found, es);
            i += j - 1;
        }
    }
}

/**
 * Filter an option line by all pull filters.
 *
 * If a match is found, the line is modified depending on
 * the filter type, and returns true. If the filter type is
 * reject, SIGUSR1 is triggered and the return value is false.
 * In that case the caller must end the push processing.
 */
static bool
apply_pull_filter(const struct options *o, char *line)
{
    struct pull_filter *f;

    if (!o->pull_filter_list)
    {
        return true;
    }

    /* skip leading spaces matching the behaviour of parse_line */
    while (isspace(*line))
    {
        line++;
    }

    for (f = o->pull_filter_list->head; f; f = f->next)
    {
        if (f->type == PUF_TYPE_ACCEPT && strncmp(line, f->pattern, f->size) == 0)
        {
            msg(D_LOW, "Pushed option accepted by filter: '%s'", line);
            return true;
        }
        else if (f->type == PUF_TYPE_IGNORE && strncmp(line, f->pattern, f->size) == 0)
        {
            msg(D_PUSH, "Pushed option removed by filter: '%s'", line);
            *line = '\0';
            return true;
        }
        else if (f->type == PUF_TYPE_REJECT && strncmp(line, f->pattern, f->size) == 0)
        {
            msg(M_WARN, "Pushed option rejected by filter: '%s'. Restarting.", line);
            *line = '\0';
            throw_signal_soft(SIGUSR1, "Offending option received from server");
            return false;
        }
    }
    return true;
}

bool
apply_push_options(struct options *options,
                   struct buffer *buf,
                   unsigned int permission_mask,
                   unsigned int *option_types_found,
                   struct env_set *es)
{
    char line[OPTION_PARM_SIZE];
    int line_num = 0;
    const char *file = "[PUSH-OPTIONS]";
    const int msglevel = D_PUSH_ERRORS|M_OPTERR;

    while (buf_parse(buf, ',', line, sizeof(line)))
    {
        char *p[MAX_PARMS+1];
        CLEAR(p);
        ++line_num;
        if (!apply_pull_filter(options, line))
        {
            return false; /* Cause push/pull error and stop push processing */
        }
        if (parse_line(line, p, SIZE(p)-1, file, line_num, msglevel, &options->gc))
        {
            add_option(options, p, false, file, line_num, 0, msglevel,
                       permission_mask, option_types_found, es);
        }
    }
    return true;
}

void
options_server_import(struct options *o,
                      const char *filename,
                      int msglevel,
                      unsigned int permission_mask,
                      unsigned int *option_types_found,
                      struct env_set *es)
{
    msg(D_PUSH, "OPTIONS IMPORT: reading client specific options from: %s", filename);
    read_config_file(o,
                     filename,
                     0,
                     filename,
                     0,
                     msglevel,
                     permission_mask,
                     option_types_found,
                     es);
}

void
options_string_import(struct options *options,
                      const char *config,
                      const int msglevel,
                      const unsigned int permission_mask,
                      unsigned int *option_types_found,
                      struct env_set *es)
{
    read_config_string("[CONFIG-STRING]", options, config, msglevel, permission_mask, option_types_found, es);
}

#define VERIFY_PERMISSION(mask) {                                            \
        if (!verify_permission(p[0], file, line, (mask), permission_mask,        \
                               option_types_found, msglevel, options, is_inline)) \
        {                                                                        \
            goto err;                                                            \
        }                                                                        \
}

static bool
verify_permission(const char *name,
                  const char *file,
                  int line,
                  const unsigned int type,
                  const unsigned int allowed,
                  unsigned int *found,
                  const int msglevel,
                  struct options *options,
                  bool is_inline)
{
    if (!(type & allowed))
    {
        msg(msglevel, "option '%s' cannot be used in this context (%s)", name, file);
        return false;
    }

    if (is_inline && !(type & OPT_P_INLINE))
    {
        msg(msglevel, "option '%s' is not expected to be inline (%s:%d)", name,
            file, line);
        return false;
    }

    if (found)
    {
        *found |= type;
    }

#ifndef ENABLE_SMALL
    /* Check if this options is allowed in connection block,
     * but we are currently not in a connection block
     * unless this is a pushed option.
     * Parsing a connection block uses a temporary options struct without
     * connection_list
     */

    if ((type & OPT_P_CONNECTION) && options->connection_list
        && !(allowed & OPT_P_PULL_MODE))
    {
        if (file)
        {
            msg(M_WARN, "Option '%s' in %s:%d is ignored by previous <connection> blocks ", name, file, line);
        }
        else
        {
            msg(M_WARN, "Option '%s' is ignored by previous <connection> blocks", name);
        }
    }
#endif
    return true;
}

/*
 * Check that an option doesn't have too
 * many parameters.
 */

#define NM_QUOTE_HINT (1<<0)

static bool
no_more_than_n_args(const int msglevel,
                    char *p[],
                    const int max,
                    const unsigned int flags)
{
    const int len = string_array_len((const char **)p);

    if (!len)
    {
        return false;
    }

    if (len > max)
    {
        msg(msglevel, "the --%s directive should have at most %d parameter%s.%s",
            p[0],
            max - 1,
            max >= 3 ? "s" : "",
            (flags & NM_QUOTE_HINT) ? "  To pass a list of arguments as one of the parameters, try enclosing them in double quotes (\"\")." : "");
        return false;
    }
    else
    {
        return true;
    }
}

static inline int
msglevel_forward_compatible(struct options *options, const int msglevel)
{
    return options->forward_compatible ? M_WARN : msglevel;
}

static void
set_user_script(struct options *options,
                const char **script,
                const char *new_script,
                const char *type,
                bool in_chroot)
{
    if (*script)
    {
        msg(M_WARN, "Multiple --%s scripts defined.  "
            "The previously configured script is overridden.", type);
    }
    *script = new_script;
    options->user_script_used = true;

#ifndef ENABLE_SMALL
    {
        char script_name[100];
        openvpn_snprintf(script_name, sizeof(script_name),
                         "--%s script", type);

        if (check_cmd_access(*script, script_name, (in_chroot ? options->chroot_dir : NULL)))
        {
            msg(M_USAGE, "Please correct this error.");
        }

    }
#endif
}

static void
show_compression_warning(struct compress_options *info)
{
    if (comp_non_stub_enabled(info))
    {
        /*
         * Check if already displayed the strong warning and enabled full
         * compression
         */
        if (!(info->flags & COMP_F_ALLOW_COMPRESS))
        {
            msg(M_WARN, "WARNING: Compression for receiving enabled. "
                "Compression has been used in the past to break encryption. "
                "Sent packets are not compressed unless \"allow-compression yes\" "
                "is also set.");
        }
    }
}

bool
key_is_external(const struct options *options)
{
    bool ret = false;
    ret = ret || (options->management_flags & MF_EXTERNAL_KEY);
#ifdef ENABLE_PKCS11
    ret = ret || (options->pkcs11_providers[0] != NULL);
#endif
#ifdef ENABLE_CRYPTOAPI
    ret = ret || options->cryptoapi_cert;
#endif

    return ret;
}

static void
add_option(struct options *options,
           char *p[],
           bool is_inline,
           const char *file,
           int line,
           const int level,
           const int msglevel,
           const unsigned int permission_mask,
           unsigned int *option_types_found,
           struct env_set *es)
{
    struct gc_arena gc = gc_new();
    const bool pull_mode = BOOL_CAST(permission_mask & OPT_P_PULL_MODE);
    int msglevel_fc = msglevel_forward_compatible(options, msglevel);

    ASSERT(MAX_PARMS >= 7);

    /*
     * If directive begins with "setenv opt" prefix, don't raise an error if
     * directive is unrecognized.
     */
    if (streq(p[0], "setenv") && p[1] && streq(p[1], "opt") && !(permission_mask & OPT_P_PULL_MODE))
    {
        if (!p[2])
        {
            p[2] = "setenv opt"; /* will trigger an error that includes setenv opt */
        }
        p += 2;
        msglevel_fc = M_WARN;
    }

    if (!file)
    {
        file = "[CMD-LINE]";
        line = 1;
    }
    if (streq(p[0], "help"))
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        usage();
        if (p[1])
        {
            msg(msglevel, "--help does not accept any parameters");
            goto err;
        }
    }
    if (streq(p[0], "version") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        usage_version();
    }
    else if (streq(p[0], "config") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_CONFIG);

        /* save first config file only in options */
        if (!options->config)
        {
            options->config = p[1];
        }

        read_config_file(options, p[1], level, file, line, msglevel, permission_mask, option_types_found, es);
    }
#if defined(ENABLE_DEBUG) && !defined(ENABLE_SMALL)
    else if (streq(p[0], "show-gateway") && !p[2])
    {
        struct route_gateway_info rgi;
        struct route_ipv6_gateway_info rgi6;
        struct in6_addr remote = IN6ADDR_ANY_INIT;
        openvpn_net_ctx_t net_ctx;
        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (p[1])
        {
            get_ipv6_addr(p[1], &remote, NULL, M_WARN);
        }
        net_ctx_init(NULL, &net_ctx);
        get_default_gateway(&rgi, &net_ctx);
        get_default_gateway_ipv6(&rgi6, &remote, &net_ctx);
        print_default_gateway(M_INFO, &rgi, &rgi6);
        openvpn_exit(OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }
#endif
    else if (streq(p[0], "echo") || streq(p[0], "parameter"))
    {
        struct buffer string = alloc_buf_gc(OPTION_PARM_SIZE, &gc);
        int j;
        bool good = true;

        VERIFY_PERMISSION(OPT_P_ECHO);

        for (j = 1; j < MAX_PARMS; ++j)
        {
            if (!p[j])
            {
                break;
            }
            if (j > 1)
            {
                good &= buf_printf(&string, " ");
            }
            good &= buf_printf(&string, "%s", p[j]);
        }
        if (good)
        {
            /* only message-related ECHO are logged, since other ECHOs
             * can potentially include security-sensitive strings */
            if (p[1] && strncmp(p[1], "msg", 3) == 0)
            {
                msg(M_INFO, "%s:%s",
                    pull_mode ? "ECHO-PULL" : "ECHO",
                    BSTR(&string));
            }
#ifdef ENABLE_MANAGEMENT
            if (management)
            {
                management_echo(management, BSTR(&string), pull_mode);
            }
#endif
        }
        else
        {
            msg(M_WARN, "echo/parameter option overflow");
        }
    }
#ifdef ENABLE_MANAGEMENT
    else if (streq(p[0], "management") && p[1] && p[2] && !p[4])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (streq(p[2], "unix"))
        {
#if UNIX_SOCK_SUPPORT
            options->management_flags |= MF_UNIX_SOCK;
#else
            msg(msglevel, "MANAGEMENT: this platform does not support unix domain sockets");
            goto err;
#endif
        }

        options->management_addr = p[1];
        options->management_port = p[2];
        if (p[3])
        {
            options->management_user_pass = p[3];
        }
    }
    else if (streq(p[0], "management-client-user") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->management_client_user = p[1];
    }
    else if (streq(p[0], "management-client-group") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->management_client_group = p[1];
    }
    else if (streq(p[0], "management-query-passwords") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->management_flags |= MF_QUERY_PASSWORDS;
    }
    else if (streq(p[0], "management-query-remote") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->management_flags |= MF_QUERY_REMOTE;
    }
    else if (streq(p[0], "management-query-proxy") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->management_flags |= MF_QUERY_PROXY;
    }
    else if (streq(p[0], "management-hold") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->management_flags |= MF_HOLD;
    }
    else if (streq(p[0], "management-signal") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->management_flags |= MF_SIGNAL;
    }
    else if (streq(p[0], "management-forget-disconnect") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->management_flags |= MF_FORGET_DISCONNECT;
    }
    else if (streq(p[0], "management-up-down") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->management_flags |= MF_UP_DOWN;
    }
    else if (streq(p[0], "management-client") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->management_flags |= MF_CONNECT_AS_CLIENT;
    }
    else if (streq(p[0], "management-external-key"))
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        for (int j = 1; j < MAX_PARMS && p[j] != NULL; ++j)
        {
            if (streq(p[j], "nopadding"))
            {
                options->management_flags |= MF_EXTERNAL_KEY_NOPADDING;
            }
            else if (streq(p[j], "pkcs1"))
            {
                options->management_flags |= MF_EXTERNAL_KEY_PKCS1PAD;
            }
            else if (streq(p[j], "pss"))
            {
                options->management_flags |= MF_EXTERNAL_KEY_PSSPAD;
            }
            else if (streq(p[j], "digest"))
            {
                options->management_flags |= MF_EXTERNAL_KEY_DIGEST;
            }
            else
            {
                msg(msglevel, "Unknown management-external-key flag: %s", p[j]);
            }
        }
        /*
         * When no option is present, assume that only PKCS1
         * padding is supported
         */
        if (!(options->management_flags
              &(MF_EXTERNAL_KEY_NOPADDING | MF_EXTERNAL_KEY_PKCS1PAD)))
        {
            options->management_flags |= MF_EXTERNAL_KEY_PKCS1PAD;
        }
        options->management_flags |= MF_EXTERNAL_KEY;
    }
    else if (streq(p[0], "management-external-cert") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->management_flags |= MF_EXTERNAL_CERT;
        options->management_certificate = p[1];
    }
    else if (streq(p[0], "management-client-auth") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->management_flags |= MF_CLIENT_AUTH;
    }
    else if (streq(p[0], "management-log-cache") && p[1] && !p[2])
    {
        int cache;

        VERIFY_PERMISSION(OPT_P_GENERAL);
        cache = atoi(p[1]);
        if (cache < 1)
        {
            msg(msglevel, "--management-log-cache parameter is out of range");
            goto err;
        }
        options->management_log_history_cache = cache;
    }
#endif /* ifdef ENABLE_MANAGEMENT */
#ifdef ENABLE_PLUGIN
    else if (streq(p[0], "plugin") && p[1])
    {
        VERIFY_PERMISSION(OPT_P_PLUGIN);
        if (!options->plugin_list)
        {
            options->plugin_list = plugin_option_list_new(&options->gc);
        }
        if (!plugin_option_list_add(options->plugin_list, &p[1], &options->gc))
        {
            msg(msglevel, "plugin add failed: %s", p[1]);
            goto err;
        }
    }
#endif
    else if (streq(p[0], "mode") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (streq(p[1], "p2p"))
        {
            options->mode = MODE_POINT_TO_POINT;
        }
        else if (streq(p[1], "server"))
        {
            options->mode = MODE_SERVER;
        }
        else
        {
            msg(msglevel, "Bad --mode parameter: %s", p[1]);
            goto err;
        }
    }
    else if (streq(p[0], "dev") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->dev = p[1];
    }
    else if (streq(p[0], "dev-type") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->dev_type = p[1];
    }
#ifdef _WIN32
    else if (streq(p[0], "windows-driver") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->windows_driver = parse_windows_driver(p[1], M_FATAL);
    }
#endif
    else if (streq(p[0], "disable-dco"))
    {
        options->tuntap_options.disable_dco = true;
    }
    else if (streq(p[0], "dev-node") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->dev_node = p[1];
    }
    else if (streq(p[0], "lladdr") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_UP);
        if (mac_addr_safe(p[1])) /* MAC address only */
        {
            options->lladdr = p[1];
        }
        else
        {
            msg(msglevel, "lladdr parm '%s' must be a MAC address", p[1]);
            goto err;
        }
    }
    else if (streq(p[0], "topology") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_UP);
        options->topology = parse_topology(p[1], msglevel);
    }
    else if (streq(p[0], "tun-ipv6") && !p[1])
    {
        if (!pull_mode)
        {
            msg(M_WARN, "Note: option tun-ipv6 is ignored because modern operating systems do not need special IPv6 tun handling anymore.");
        }
    }
#ifdef ENABLE_IPROUTE
    else if (streq(p[0], "iproute") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        iproute_path = p[1];
    }
#endif
    else if (streq(p[0], "ifconfig") && p[1] && p[2] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_UP);
        if (ip_or_dns_addr_safe(p[1], options->allow_pull_fqdn) && ip_or_dns_addr_safe(p[2], options->allow_pull_fqdn)) /* FQDN -- may be DNS name */
        {
            options->ifconfig_local = p[1];
            options->ifconfig_remote_netmask = p[2];
        }
        else
        {
            msg(msglevel, "ifconfig parms '%s' and '%s' must be valid addresses", p[1], p[2]);
            goto err;
        }
    }
    else if (streq(p[0], "ifconfig-ipv6") && p[1] && p[2] && !p[3])
    {
        unsigned int netbits;

        VERIFY_PERMISSION(OPT_P_UP);
        if (get_ipv6_addr( p[1], NULL, &netbits, msglevel )
            && ipv6_addr_safe( p[2] ) )
        {
            if (netbits < 64 || netbits > 124)
            {
                msg( msglevel, "ifconfig-ipv6: /netbits must be between 64 and 124, not '/%d'", netbits );
                goto err;
            }

            options->ifconfig_ipv6_local = get_ipv6_addr_no_netbits(p[1], &options->gc);
            options->ifconfig_ipv6_netbits = netbits;
            options->ifconfig_ipv6_remote = p[2];
        }
        else
        {
            msg(msglevel, "ifconfig-ipv6 parms '%s' and '%s' must be valid addresses", p[1], p[2]);
            goto err;
        }
    }
    else if (streq(p[0], "ifconfig-noexec") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_UP);
        options->ifconfig_noexec = true;
    }
    else if (streq(p[0], "ifconfig-nowarn") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_UP);
        options->ifconfig_nowarn = true;
    }
    else if (streq(p[0], "local") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        options->ce.local = p[1];
    }
    else if (streq(p[0], "remote-random") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->remote_random = true;
    }
    else if (streq(p[0], "connection") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_INLINE);
        if (is_inline)
        {
            struct options sub;
            struct connection_entry *e;

            init_options(&sub, true);
            sub.ce = options->ce;
            read_config_string("[CONNECTION-OPTIONS]", &sub, p[1], msglevel,
                               OPT_P_CONNECTION, option_types_found, es);
            if (!sub.ce.remote)
            {
                msg(msglevel, "Each 'connection' block must contain exactly one 'remote' directive");
                uninit_options(&sub);
                goto err;
            }

            e = alloc_connection_entry(options, msglevel);
            if (!e)
            {
                uninit_options(&sub);
                goto err;
            }
            *e = sub.ce;
            gc_transfer(&options->gc, &sub.gc);
            uninit_options(&sub);
        }
    }
    else if (streq(p[0], "ignore-unknown-option") && p[1])
    {
        int i;
        int j;
        int numignored = 0;
        const char **ignore;

        VERIFY_PERMISSION(OPT_P_GENERAL);
        /* Find out how many options to be ignored */
        for (i = 1; p[i]; i++)
        {
            numignored++;
        }

        /* add number of options already ignored */
        for (i = 0; options->ignore_unknown_option
             && options->ignore_unknown_option[i]; i++)
        {
            numignored++;
        }

        /* Allocate array */
        ALLOC_ARRAY_GC(ignore, const char *, numignored+1, &options->gc);
        for (i = 0; options->ignore_unknown_option
             && options->ignore_unknown_option[i]; i++)
        {
            ignore[i] = options->ignore_unknown_option[i];
        }

        options->ignore_unknown_option = ignore;

        for (j = 1; p[j]; j++)
        {
            /* Allow the user to specify ignore-unknown-option --opt too */
            if (p[j][0]=='-' && p[j][1]=='-')
            {
                options->ignore_unknown_option[i] = (p[j]+2);
            }
            else
            {
                options->ignore_unknown_option[i] = p[j];
            }
            i++;
        }

        options->ignore_unknown_option[i] = NULL;
    }
#if ENABLE_MANAGEMENT
    else if (streq(p[0], "http-proxy-override") && p[1] && p[2] && !p[4])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->http_proxy_override = parse_http_proxy_override(p[1], p[2], p[3], msglevel, &options->gc);
        if (!options->http_proxy_override)
        {
            goto err;
        }
    }
#endif
    else if (streq(p[0], "remote") && p[1] && !p[4])
    {
        struct remote_entry re;
        re.remote = re.remote_port = NULL;
        re.proto = -1;
        re.af = 0;

        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        re.remote = p[1];
        if (p[2])
        {
            re.remote_port = p[2];
            if (p[3])
            {
                const int proto = ascii2proto(p[3]);
                const sa_family_t af = ascii2af(p[3]);
                if (proto < 0)
                {
                    msg(msglevel,
                        "remote: bad protocol associated with host %s: '%s'",
                        p[1], p[3]);
                    goto err;
                }
                re.proto = proto;
                re.af = af;
            }
        }
        if (permission_mask & OPT_P_GENERAL)
        {
            struct remote_entry *e = alloc_remote_entry(options, msglevel);
            if (!e)
            {
                goto err;
            }
            *e = re;
        }
        else if (permission_mask & OPT_P_CONNECTION)
        {
            connection_entry_load_re(&options->ce, &re);
        }
    }
    else if (streq(p[0], "resolv-retry") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (streq(p[1], "infinite"))
        {
            options->resolve_retry_seconds = RESOLV_RETRY_INFINITE;
        }
        else
        {
            options->resolve_retry_seconds = positive_atoi(p[1]);
        }
    }
    else if ((streq(p[0], "preresolve") || streq(p[0], "ip-remote-hint")) && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->resolve_in_advance = true;
        /* Note the ip-remote-hint and the argument p[1] are for
         * backward compatibility */
        if (p[1])
        {
            options->ip_remote_hint = p[1];
        }
    }
    else if (streq(p[0], "connect-retry") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        options->ce.connect_retry_seconds = positive_atoi(p[1]);
        /*
         * Limit the base value of retry wait interval to 16 bits to avoid
         * overflow when scaled up for exponential backoff
         */
        if (options->ce.connect_retry_seconds > 0xFFFF)
        {
            options->ce.connect_retry_seconds = 0xFFFF;
            msg(M_WARN, "connect retry wait interval truncated to %d",
                options->ce.connect_retry_seconds);
        }

        if (p[2])
        {
            options->ce.connect_retry_seconds_max =
                max_int(positive_atoi(p[2]), options->ce.connect_retry_seconds);
        }
    }
    else if ((streq(p[0], "connect-timeout") || streq(p[0], "server-poll-timeout"))
             && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        options->ce.connect_timeout = positive_atoi(p[1]);
    }
    else if (streq(p[0], "connect-retry-max") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        options->connect_retry_max = positive_atoi(p[1]);
    }
    else if (streq(p[0], "ipchange") && p[1])
    {
        VERIFY_PERMISSION(OPT_P_SCRIPT);
        if (!no_more_than_n_args(msglevel, p, 2, NM_QUOTE_HINT))
        {
            goto err;
        }
        set_user_script(options,
                        &options->ipchange,
                        string_substitute(p[1], ',', ' ', &options->gc),
                        "ipchange", true);
    }
    else if (streq(p[0], "float") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        options->ce.remote_float = true;
    }
#ifdef ENABLE_DEBUG
    else if (streq(p[0], "gremlin") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->gremlin = positive_atoi(p[1]);
    }
#endif
    else if (streq(p[0], "chroot") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->chroot_dir = p[1];
    }
    else if (streq(p[0], "cd") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (platform_chdir(p[1]))
        {
            msg(M_ERR, "cd to '%s' failed", p[1]);
            goto err;
        }
        options->cd_dir = p[1];
    }
#ifdef ENABLE_SELINUX
    else if (streq(p[0], "setcon") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->selinux_context = p[1];
    }
#endif
    else if (streq(p[0], "writepid") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->writepid = p[1];
    }
    else if (streq(p[0], "up") && p[1])
    {
        VERIFY_PERMISSION(OPT_P_SCRIPT);
        if (!no_more_than_n_args(msglevel, p, 2, NM_QUOTE_HINT))
        {
            goto err;
        }
        set_user_script(options, &options->up_script, p[1], "up", false);
    }
    else if (streq(p[0], "down") && p[1])
    {
        VERIFY_PERMISSION(OPT_P_SCRIPT);
        if (!no_more_than_n_args(msglevel, p, 2, NM_QUOTE_HINT))
        {
            goto err;
        }
        set_user_script(options, &options->down_script, p[1], "down", true);
    }
    else if (streq(p[0], "down-pre") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->down_pre = true;
    }
    else if (streq(p[0], "up-delay") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->up_delay = true;
    }
    else if (streq(p[0], "up-restart") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->up_restart = true;
    }
    else if (streq(p[0], "syslog") && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        open_syslog(p[1], false);
    }
    else if (streq(p[0], "daemon") && !p[2])
    {
        bool didit = false;
        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (!options->daemon)
        {
            options->daemon = didit = true;
            open_syslog(p[1], false);
        }
        if (p[1])
        {
            if (!didit)
            {
                msg(M_WARN, "WARNING: Multiple --daemon directives specified, ignoring --daemon %s. (Note that initscripts sometimes add their own --daemon directive.)", p[1]);
                goto err;
            }
        }
    }
    else if (streq(p[0], "log") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->log = true;
        redirect_stdout_stderr(p[1], false);
    }
    else if (streq(p[0], "suppress-timestamps") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->suppress_timestamps = true;
        set_suppress_timestamps(true);
    }
    else if (streq(p[0], "machine-readable-output") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->machine_readable_output = true;
        set_machine_readable_output(true);
    }
    else if (streq(p[0], "log-append") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->log = true;
        redirect_stdout_stderr(p[1], true);
    }
#ifdef ENABLE_MEMSTATS
    else if (streq(p[0], "memstats") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->memstats_fn = p[1];
    }
#endif
    else if (streq(p[0], "mlock") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->mlock = true;
    }
#if ENABLE_IP_PKTINFO
    else if (streq(p[0], "multihome") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->sockflags |= SF_USE_IP_PKTINFO;
    }
#endif
    else if (streq(p[0], "verb") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_MESSAGES);
        options->verbosity = positive_atoi(p[1]);
        if (options->verbosity >= (D_TLS_DEBUG_MED & M_DEBUG_LEVEL))
        {
            /* We pass this flag to the SSL library to avoid
             * mbed TLS always generating debug level logging */
            options->ssl_flags |= SSLF_TLS_DEBUG_ENABLED;
        }
#if !defined(ENABLE_DEBUG) && !defined(ENABLE_SMALL)
        /* Warn when a debug verbosity is supplied when built without debug support */
        if (options->verbosity >= 7)
        {
            msg(M_WARN, "NOTE: debug verbosity (--verb %d) is enabled but this build lacks debug support.",
                options->verbosity);
        }
#endif
    }
    else if (streq(p[0], "mute") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_MESSAGES);
        options->mute = positive_atoi(p[1]);
    }
    else if (streq(p[0], "errors-to-stderr") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_MESSAGES);
        errors_to_stderr();
    }
    else if (streq(p[0], "status") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->status_file = p[1];
        if (p[2])
        {
            options->status_file_update_freq = positive_atoi(p[2]);
        }
    }
    else if (streq(p[0], "status-version") && p[1] && !p[2])
    {
        int version;

        VERIFY_PERMISSION(OPT_P_GENERAL);
        version = atoi(p[1]);
        if (version < 1 || version > 3)
        {
            msg(msglevel, "--status-version must be 1 to 3");
            goto err;
        }
        options->status_file_version = version;
    }
    else if (streq(p[0], "remap-usr1") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (streq(p[1], "SIGHUP"))
        {
            options->remap_sigusr1 = SIGHUP;
        }
        else if (streq(p[1], "SIGTERM"))
        {
            options->remap_sigusr1 = SIGTERM;
        }
        else
        {
            msg(msglevel, "--remap-usr1 parm must be 'SIGHUP' or 'SIGTERM'");
            goto err;
        }
    }
    else if ((streq(p[0], "link-mtu") || streq(p[0], "udp-mtu")) && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_MTU|OPT_P_CONNECTION);
        options->ce.link_mtu = positive_atoi(p[1]);
        options->ce.link_mtu_defined = true;
    }
    else if (streq(p[0], "tun-mtu") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_PUSH_MTU|OPT_P_CONNECTION);
        options->ce.tun_mtu = positive_atoi(p[1]);
        options->ce.tun_mtu_defined = true;
        if (p[2])
        {
            options->ce.occ_mtu = positive_atoi(p[2]);
        }
        else
        {
            options->ce.occ_mtu = 0;
        }
    }
    else if (streq(p[0], "tun-mtu-max") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_MTU|OPT_P_CONNECTION);
        int max_mtu = positive_atoi(p[1]);
        if (max_mtu < 68 || max_mtu > 65536)
        {
            msg(msglevel, "--tun-mtu-max value '%s' is invalid", p[1]);
        }
        else
        {
            options->ce.tun_mtu_max = max_mtu;
        }
    }
    else if (streq(p[0], "tun-mtu-extra") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_MTU|OPT_P_CONNECTION);
        options->ce.tun_mtu_extra = positive_atoi(p[1]);
        options->ce.tun_mtu_extra_defined = true;
    }
    else if (streq(p[0], "max-packet-size") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_MTU|OPT_P_CONNECTION);
        int maxmtu = positive_atoi(p[1]);
        options->ce.tls_mtu = constrain_int(maxmtu, TLS_CHANNEL_MTU_MIN, TLS_CHANNEL_BUF_SIZE);

        if (maxmtu < TLS_CHANNEL_MTU_MIN || maxmtu > TLS_CHANNEL_BUF_SIZE)
        {
            msg(M_WARN, "Note: max-packet-size value outside of allowed "
                "control channel packet size (%d to %d), will use %d "
                "instead.", TLS_CHANNEL_MTU_MIN, TLS_CHANNEL_BUF_SIZE,
                options->ce.tls_mtu);
        }

        /* also set mssfix maxmtu mtu */
        options->ce.mssfix = maxmtu;
        options->ce.mssfix_default = false;
        options->ce.mssfix_encap = true;
    }
#ifdef ENABLE_FRAGMENT
    else if (streq(p[0], "mtu-dynamic"))
    {
        VERIFY_PERMISSION(OPT_P_MTU|OPT_P_CONNECTION);
        msg(msglevel, "--mtu-dynamic has been replaced by --fragment");
        goto err;
    }
    else if (streq(p[0], "fragment") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_MTU|OPT_P_CONNECTION);
        options->ce.fragment = positive_atoi(p[1]);

        if (options->ce.fragment < 68)
        {
            msg(msglevel, "--fragment needs to be at least 68");
            goto err;
        }

        if (p[2] && streq(p[2], "mtu"))
        {
            options->ce.fragment_encap = true;
        }
        else if (p[2])
        {
            msg(msglevel, "Unknown parameter to --fragment: %s", p[2]);
        }
    }
#endif /* ifdef ENABLE_FRAGMENT */
    else if (streq(p[0], "mtu-disc") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_MTU|OPT_P_CONNECTION);
        options->ce.mtu_discover_type = translate_mtu_discover_type_name(p[1]);
    }
    else if (streq(p[0], "mtu-test") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->mtu_test = true;
    }
    else if (streq(p[0], "nice") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_NICE);
        options->nice = atoi(p[1]);
    }
    else if (streq(p[0], "rcvbuf") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_SOCKBUF);
        options->rcvbuf = positive_atoi(p[1]);
    }
    else if (streq(p[0], "sndbuf") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_SOCKBUF);
        options->sndbuf = positive_atoi(p[1]);
    }
    else if (streq(p[0], "mark") && p[1] && !p[2])
    {
#if defined(TARGET_LINUX) && HAVE_DECL_SO_MARK
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->mark = atoi(p[1]);
#endif
    }
    else if (streq(p[0], "socket-flags"))
    {
        int j;
        VERIFY_PERMISSION(OPT_P_SOCKFLAGS);
        for (j = 1; j < MAX_PARMS && p[j]; ++j)
        {
            if (streq(p[j], "TCP_NODELAY"))
            {
                options->sockflags |= SF_TCP_NODELAY;
            }
            else
            {
                msg(msglevel, "unknown socket flag: %s", p[j]);
            }
        }
    }
#ifdef TARGET_LINUX
    else if (streq(p[0], "bind-dev") && p[1])
    {
        VERIFY_PERMISSION(OPT_P_SOCKFLAGS);
        options->bind_dev = p[1];
    }
#endif
    else if (streq(p[0], "txqueuelen") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
#ifdef TARGET_LINUX
        options->tuntap_options.txqueuelen = positive_atoi(p[1]);
#else
        msg(msglevel, "--txqueuelen not supported on this OS");
        goto err;
#endif
    }
    else if (streq(p[0], "shaper") && p[1] && !p[2])
    {
        int shaper;

        VERIFY_PERMISSION(OPT_P_SHAPER);
        shaper = atoi(p[1]);
        if (shaper < SHAPER_MIN || shaper > SHAPER_MAX)
        {
            msg(msglevel, "Bad shaper value, must be between %d and %d",
                SHAPER_MIN, SHAPER_MAX);
            goto err;
        }
        options->shaper = shaper;
    }
    else if (streq(p[0], "port") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        options->ce.local_port = options->ce.remote_port = p[1];
    }
    else if (streq(p[0], "lport") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        options->ce.local_port_defined = true;
        options->ce.local_port = p[1];
    }
    else if (streq(p[0], "rport") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        options->ce.remote_port = p[1];
    }
    else if (streq(p[0], "bind") && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        options->ce.bind_defined = true;
        if (p[1] && streq(p[1], "ipv6only"))
        {
            options->ce.bind_ipv6_only = true;
        }

    }
    else if (streq(p[0], "nobind") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        options->ce.bind_local = false;
    }
    else if (streq(p[0], "fast-io") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->fast_io = true;
    }
    else if (streq(p[0], "inactive") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_TIMER);
        options->inactivity_timeout = positive_atoi(p[1]);
        if (p[2])
        {
            int64_t val = atoll(p[2]);
            options->inactivity_minimum_bytes = (val < 0) ? 0 : val;
            if (options->inactivity_minimum_bytes > INT_MAX)
            {
                msg(M_WARN, "WARNING: '--inactive' with a 'bytes' value"
                    " >2 Gbyte was silently ignored in older versions.  If "
                    " your VPN exits unexpectedly with 'Inactivity timeout'"
                    " in %d seconds, revisit this value.",
                    options->inactivity_timeout );
            }
        }
    }
    else if (streq(p[0], "session-timeout") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_TIMER);
        options->session_timeout = positive_atoi(p[1]);
    }
    else if (streq(p[0], "proto") && p[1] && !p[2])
    {
        int proto;
        sa_family_t af;
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        proto = ascii2proto(p[1]);
        af = ascii2af(p[1]);
        if (proto < 0)
        {
            msg(msglevel,
                "Bad protocol: '%s'. Allowed protocols with --proto option: %s",
                p[1],
                proto2ascii_all(&gc));
            goto err;
        }
        options->ce.proto = proto;
        options->ce.af = af;
    }
    else if (streq(p[0], "proto-force") && p[1] && !p[2])
    {
        int proto_force;
        VERIFY_PERMISSION(OPT_P_GENERAL);
        proto_force = ascii2proto(p[1]);
        if (proto_force < 0)
        {
            msg(msglevel, "Bad --proto-force protocol: '%s'", p[1]);
            goto err;
        }
        options->proto_force = proto_force;
    }
    else if (streq(p[0], "http-proxy") && p[1] && !p[5])
    {
        struct http_proxy_options *ho;

        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);

        {
            if (!p[2])
            {
                msg(msglevel, "http-proxy port number not defined");
                goto err;
            }

            ho = init_http_proxy_options_once(&options->ce.http_proxy_options, &options->gc);

            ho->server = p[1];
            ho->port = p[2];
        }

        if (p[3])
        {
            /* auto -- try to figure out proxy addr, port, and type automatically */
            /* semiauto -- given proxy addr:port, try to figure out type automatically */
            /* (auto|semiauto)-nct -- disable proxy auth cleartext protocols (i.e. basic auth) */
            if (streq(p[3], "auto"))
            {
                ho->auth_retry = PAR_ALL;
            }
            else if (streq(p[3], "auto-nct"))
            {
                ho->auth_retry = PAR_NCT;
            }
            else
            {
                ho->auth_method_string = "basic";
                ho->auth_file = p[3];

                if (p[4])
                {
                    ho->auth_method_string = p[4];
                }
            }
        }
        else
        {
            ho->auth_method_string = "none";
        }
    }
    else if (streq(p[0], "http-proxy-user-pass") && p[1])
    {
        struct http_proxy_options *ho;
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_INLINE);
        ho = init_http_proxy_options_once(&options->ce.http_proxy_options, &options->gc);
        ho->auth_file_up = p[1];
        ho->inline_creds = is_inline;
    }
    else if (streq(p[0], "http-proxy-retry") || streq(p[0], "socks-proxy-retry"))
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        msg(M_WARN, "DEPRECATED OPTION: http-proxy-retry and socks-proxy-retry: "
            "In OpenVPN 2.4 proxy connection retries are handled like regular connections. "
            "Use connect-retry-max 1 to get a similar behavior as before.");
    }
    else if (streq(p[0], "http-proxy-timeout") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        msg(M_WARN, "DEPRECATED OPTION: http-proxy-timeout: In OpenVPN 2.4 the timeout until a connection to a "
            "server is established is managed with a single timeout set by connect-timeout");
    }
    else if (streq(p[0], "http-proxy-option") && p[1] && !p[4])
    {
        struct http_proxy_options *ho;

        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        ho = init_http_proxy_options_once(&options->ce.http_proxy_options, &options->gc);

        if (streq(p[1], "VERSION") && p[2] && !p[3])
        {
            ho->http_version = p[2];
        }
        else if (streq(p[1], "AGENT") && p[2] && !p[3])
        {
            ho->user_agent = p[2];
        }
        else if ((streq(p[1], "EXT1") || streq(p[1], "EXT2") || streq(p[1], "CUSTOM-HEADER"))
                 && p[2])
        {
            /* In the wild patched versions use both EXT1/2 and CUSTOM-HEADER
             * with either two argument or one */

            struct http_custom_header *custom_header = NULL;
            int i;
            /* Find the first free header */
            for (i = 0; i < MAX_CUSTOM_HTTP_HEADER; i++)
            {
                if (!ho->custom_headers[i].name)
                {
                    custom_header = &ho->custom_headers[i];
                    break;
                }
            }
            if (!custom_header)
            {
                msg(msglevel, "Cannot use more than %d http-proxy-option CUSTOM-HEADER : '%s'", MAX_CUSTOM_HTTP_HEADER, p[1]);
            }
            else
            {
                /* We will save p[2] and p[3], the proxy code will detect if
                 * p[3] is NULL */
                custom_header->name = p[2];
                custom_header->content = p[3];
            }
        }
        else
        {
            msg(msglevel, "Bad http-proxy-option or missing or extra parameter: '%s'", p[1]);
        }
    }
    else if (streq(p[0], "socks-proxy") && p[1] && !p[4])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);

        if (p[2])
        {
            options->ce.socks_proxy_port = p[2];
        }
        else
        {
            options->ce.socks_proxy_port = "1080";
        }
        options->ce.socks_proxy_server = p[1];
        options->ce.socks_proxy_authfile = p[3]; /* might be NULL */
    }
    else if (streq(p[0], "keepalive") && p[1] && p[2] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->keepalive_ping = atoi(p[1]);
        options->keepalive_timeout = atoi(p[2]);
    }
    else if (streq(p[0], "ping") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_TIMER);
        options->ping_send_timeout = positive_atoi(p[1]);
    }
    else if (streq(p[0], "ping-exit") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_TIMER);
        options->ping_rec_timeout = positive_atoi(p[1]);
        options->ping_rec_timeout_action = PING_EXIT;
    }
    else if (streq(p[0], "ping-restart") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_TIMER);
        options->ping_rec_timeout = positive_atoi(p[1]);
        options->ping_rec_timeout_action = PING_RESTART;
    }
    else if (streq(p[0], "ping-timer-rem") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_TIMER);
        options->ping_timer_remote = true;
    }
    else if (streq(p[0], "explicit-exit-notify") && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION|OPT_P_EXPLICIT_NOTIFY);
        if (p[1])
        {
            options->ce.explicit_exit_notification = positive_atoi(p[1]);
        }
        else
        {
            options->ce.explicit_exit_notification = 1;
        }
    }
    else if (streq(p[0], "persist-tun") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_PERSIST);
        options->persist_tun = true;
    }
    else if (streq(p[0], "persist-key") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_PERSIST);
        options->persist_key = true;
    }
    else if (streq(p[0], "persist-local-ip") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_PERSIST_IP);
        options->persist_local_ip = true;
    }
    else if (streq(p[0], "persist-remote-ip") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_PERSIST_IP);
        options->persist_remote_ip = true;
    }
    else if (streq(p[0], "client-nat") && p[1] && p[2] && p[3] && p[4] && !p[5])
    {
        VERIFY_PERMISSION(OPT_P_ROUTE);
        cnol_check_alloc(options);
        add_client_nat_to_option_list(options->client_nat, p[1], p[2], p[3], p[4], msglevel);
    }
    else if (streq(p[0], "route") && p[1] && !p[5])
    {
        VERIFY_PERMISSION(OPT_P_ROUTE);
        rol_check_alloc(options);
        if (pull_mode)
        {
            if (!ip_or_dns_addr_safe(p[1], options->allow_pull_fqdn) && !is_special_addr(p[1])) /* FQDN -- may be DNS name */
            {
                msg(msglevel, "route parameter network/IP '%s' must be a valid address", p[1]);
                goto err;
            }
            if (p[2] && !ip_addr_dotted_quad_safe(p[2])) /* FQDN -- must be IP address */
            {
                msg(msglevel, "route parameter netmask '%s' must be an IP address", p[2]);
                goto err;
            }
            if (p[3] && !ip_or_dns_addr_safe(p[3], options->allow_pull_fqdn) && !is_special_addr(p[3])) /* FQDN -- may be DNS name */
            {
                msg(msglevel, "route parameter gateway '%s' must be a valid address", p[3]);
                goto err;
            }
        }
        add_route_to_option_list(options->routes, p[1], p[2], p[3], p[4]);
    }
    else if (streq(p[0], "route-ipv6") && p[1] && !p[4])
    {
        VERIFY_PERMISSION(OPT_P_ROUTE);
        rol6_check_alloc(options);
        if (pull_mode)
        {
            if (!ipv6_addr_safe_hexplusbits(p[1]))
            {
                msg(msglevel, "route-ipv6 parameter network/IP '%s' must be a valid address", p[1]);
                goto err;
            }
            if (p[2] && !ipv6_addr_safe(p[2]))
            {
                msg(msglevel, "route-ipv6 parameter gateway '%s' must be a valid address", p[2]);
                goto err;
            }
            /* p[3] is metric, if present */
        }
        add_route_ipv6_to_option_list(options->routes_ipv6, p[1], p[2], p[3]);
    }
    else if (streq(p[0], "max-routes") && !p[2])
    {
        msg(M_WARN, "DEPRECATED OPTION: --max-routes option ignored."
            "The number of routes is unlimited as of OpenVPN 2.4. "
            "This option will be removed in a future version, "
            "please remove it from your configuration.");
    }
    else if (streq(p[0], "route-gateway") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_ROUTE_EXTRAS);
        if (streq(p[1], "dhcp"))
        {
            options->route_gateway_via_dhcp = true;
        }
        else
        {
            if (ip_or_dns_addr_safe(p[1], options->allow_pull_fqdn) || is_special_addr(p[1])) /* FQDN -- may be DNS name */
            {
                options->route_default_gateway = p[1];
            }
            else
            {
                msg(msglevel, "route-gateway parm '%s' must be a valid address", p[1]);
                goto err;
            }
        }
    }
    else if (streq(p[0], "route-ipv6-gateway") && p[1] && !p[2])
    {
        if (ipv6_addr_safe(p[1]))
        {
            options->route_ipv6_default_gateway = p[1];
        }
        else
        {
            msg(msglevel, "route-ipv6-gateway parm '%s' must be a valid address", p[1]);
            goto err;
        }
    }
    else if (streq(p[0], "route-metric") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_ROUTE);
        options->route_default_metric = positive_atoi(p[1]);
    }
    else if (streq(p[0], "route-delay") && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_ROUTE_EXTRAS);
        options->route_delay_defined = true;
        if (p[1])
        {
            options->route_delay = positive_atoi(p[1]);
            if (p[2])
            {
                options->route_delay_window = positive_atoi(p[2]);
            }
        }
        else
        {
            options->route_delay = 0;
        }
    }
    else if (streq(p[0], "route-up") && p[1])
    {
        VERIFY_PERMISSION(OPT_P_SCRIPT);
        if (!no_more_than_n_args(msglevel, p, 2, NM_QUOTE_HINT))
        {
            goto err;
        }
        set_user_script(options, &options->route_script, p[1], "route-up", false);
    }
    else if (streq(p[0], "route-pre-down") && p[1])
    {
        VERIFY_PERMISSION(OPT_P_SCRIPT);
        if (!no_more_than_n_args(msglevel, p, 2, NM_QUOTE_HINT))
        {
            goto err;
        }
        set_user_script(options,
                        &options->route_predown_script,
                        p[1],
                        "route-pre-down", true);
    }
    else if (streq(p[0], "route-noexec") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_SCRIPT);
        options->route_noexec = true;
    }
    else if (streq(p[0], "route-nopull") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->route_nopull = true;
    }
    else if (streq(p[0], "pull-filter") && p[1] && p[2] && !p[3])
    {
        struct pull_filter *f;
        VERIFY_PERMISSION(OPT_P_GENERAL)
        f = alloc_pull_filter(options, msglevel);

        if (strcmp("accept", p[1]) == 0)
        {
            f->type = PUF_TYPE_ACCEPT;
        }
        else if (strcmp("ignore", p[1]) == 0)
        {
            f->type = PUF_TYPE_IGNORE;
        }
        else if (strcmp("reject", p[1]) == 0)
        {
            f->type = PUF_TYPE_REJECT;
        }
        else
        {
            msg(msglevel, "Unknown --pull-filter type: %s", p[1]);
            goto err;
        }
        f->pattern = p[2];
        f->size = strlen(p[2]);
    }
    else if (streq(p[0], "allow-pull-fqdn") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->allow_pull_fqdn = true;
    }
    else if (streq(p[0], "redirect-gateway") || streq(p[0], "redirect-private"))
    {
        int j;
        VERIFY_PERMISSION(OPT_P_ROUTE);
        rol_check_alloc(options);

        if (options->routes->flags & RG_ENABLE)
        {
            msg(M_WARN,
                "WARNING: You have specified redirect-gateway and "
                "redirect-private at the same time (or the same option "
                "multiple times). This is not well supported and may lead to "
                "unexpected results");
        }

        options->routes->flags |= RG_ENABLE;

        if (streq(p[0], "redirect-gateway"))
        {
            options->routes->flags |= RG_REROUTE_GW;
        }
        for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j)
        {
            if (streq(p[j], "local"))
            {
                options->routes->flags |= RG_LOCAL;
            }
            else if (streq(p[j], "autolocal"))
            {
                options->routes->flags |= RG_AUTO_LOCAL;
            }
            else if (streq(p[j], "def1"))
            {
                options->routes->flags |= RG_DEF1;
            }
            else if (streq(p[j], "bypass-dhcp"))
            {
                options->routes->flags |= RG_BYPASS_DHCP;
            }
            else if (streq(p[j], "bypass-dns"))
            {
                options->routes->flags |= RG_BYPASS_DNS;
            }
            else if (streq(p[j], "block-local"))
            {
                options->routes->flags |= RG_BLOCK_LOCAL;
            }
            else if (streq(p[j], "ipv6"))
            {
                rol6_check_alloc(options);
                options->routes_ipv6->flags |= RG_REROUTE_GW;
            }
            else if (streq(p[j], "!ipv4"))
            {
                options->routes->flags &= ~(RG_REROUTE_GW | RG_ENABLE);
            }
            else
            {
                msg(msglevel, "unknown --%s flag: %s", p[0], p[j]);
                goto err;
            }
        }
#ifdef _WIN32
        /* we need this here to handle pushed --redirect-gateway */
        remap_redirect_gateway_flags(options);
#endif
    }
    else if (streq(p[0], "block-ipv6") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_ROUTE);
        options->block_ipv6 = true;
    }
    else if (streq(p[0], "remote-random-hostname") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->sockflags |= SF_HOST_RANDOMIZE;
    }
    else if (streq(p[0], "setenv") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (streq(p[1], "REMOTE_RANDOM_HOSTNAME") && !p[2])
        {
            options->sockflags |= SF_HOST_RANDOMIZE;
        }
        else if (streq(p[1], "GENERIC_CONFIG"))
        {
            msg(msglevel, "this is a generic configuration and cannot directly be used");
            goto err;
        }
        else if (streq(p[1], "PUSH_PEER_INFO") && !p[2])
        {
            options->push_peer_info = true;
        }
        else if (streq(p[1], "SERVER_POLL_TIMEOUT") && p[2])
        {
            options->ce.connect_timeout = positive_atoi(p[2]);
        }
        else
        {
            if (streq(p[1], "FORWARD_COMPATIBLE") && p[2] && streq(p[2], "1"))
            {
                options->forward_compatible = true;
                msglevel_fc = msglevel_forward_compatible(options, msglevel);
            }
            setenv_str(es, p[1], p[2] ? p[2] : "");
        }
    }
    else if (streq(p[0], "compat-mode") && p[1] && !p[3])
    {
        unsigned int major, minor, patch;
        if (!(sscanf(p[1], "%u.%u.%u", &major, &minor, &patch) == 3))
        {
            msg(msglevel, "cannot parse version number for --compat-mode: %s",
                p[1]);
            goto err;
        }

        options->backwards_compatible = major * 10000 + minor * 100 + patch;
    }
    else if (streq(p[0], "setenv-safe") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_SETENV);
        setenv_str_safe(es, p[1], p[2] ? p[2] : "");
    }
    else if (streq(p[0], "script-security") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        script_security_set(atoi(p[1]));
    }
    else if (streq(p[0], "mssfix") && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        if (p[1])
        {
            /* value specified, assume encapsulation is not
             * included unless "mtu" follows later */
            options->ce.mssfix = positive_atoi(p[1]);
            options->ce.mssfix_encap = false;
            options->ce.mssfix_default = false;
        }
        else
        {
            /* Set MTU to default values */
            options->ce.mssfix_default = true;
            options->ce.mssfix_encap = true;
            options->ce.mssfix_fixed = false;
        }

        if (p[2] && streq(p[2], "mtu"))
        {
            options->ce.mssfix_encap = true;
        }
        else if (p[2] && streq(p[2], "fixed"))
        {
            options->ce.mssfix_fixed = true;
        }
        else if (p[2])
        {
            msg(msglevel, "Unknown parameter to --mssfix: %s", p[2]);
        }
    }
    else if (streq(p[0], "disable-occ") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->occ = false;
    }
    else if (streq(p[0], "server") && p[1] && p[2] && !p[4])
    {
        const int lev = M_WARN;
        bool error = false;
        in_addr_t network, netmask;

        VERIFY_PERMISSION(OPT_P_GENERAL);
        network = get_ip_addr(p[1], lev, &error);
        netmask = get_ip_addr(p[2], lev, &error);
        if (error || !network || !netmask)
        {
            msg(msglevel, "error parsing --server parameters");
            goto err;
        }
        options->server_defined = true;
        options->server_network = network;
        options->server_netmask = netmask;

        if (p[3])
        {
            if (streq(p[3], "nopool"))
            {
                options->server_flags |= SF_NOPOOL;
            }
            else
            {
                msg(msglevel, "error parsing --server: %s is not a recognized flag", p[3]);
                goto err;
            }
        }
    }
    else if (streq(p[0], "server-ipv6") && p[1] && !p[2])
    {
        const int lev = M_WARN;
        struct in6_addr network;
        unsigned int netbits = 0;

        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (!get_ipv6_addr(p[1], &network, &netbits, lev) )
        {
            msg(msglevel, "error parsing --server-ipv6 parameter");
            goto err;
        }
        if (netbits < 64 || netbits > 124)
        {
            msg(msglevel,
                "--server-ipv6 settings: network must be between /64 and /124 (not /%d)",
                netbits);

            goto err;
        }
        options->server_ipv6_defined = true;
        options->server_network_ipv6 = network;
        options->server_netbits_ipv6 = netbits;
    }
    else if (streq(p[0], "server-bridge") && p[1] && p[2] && p[3] && p[4] && !p[5])
    {
        const int lev = M_WARN;
        bool error = false;
        in_addr_t ip, netmask, pool_start, pool_end;

        VERIFY_PERMISSION(OPT_P_GENERAL);
        ip = get_ip_addr(p[1], lev, &error);
        netmask = get_ip_addr(p[2], lev, &error);
        pool_start = get_ip_addr(p[3], lev, &error);
        pool_end = get_ip_addr(p[4], lev, &error);
        if (error || !ip || !netmask || !pool_start || !pool_end)
        {
            msg(msglevel, "error parsing --server-bridge parameters");
            goto err;
        }
        options->server_bridge_defined = true;
        options->server_bridge_ip = ip;
        options->server_bridge_netmask = netmask;
        options->server_bridge_pool_start = pool_start;
        options->server_bridge_pool_end = pool_end;
    }
    else if (streq(p[0], "server-bridge") && p[1] && streq(p[1], "nogw") && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->server_bridge_proxy_dhcp = true;
        options->server_flags |= SF_NO_PUSH_ROUTE_GATEWAY;
    }
    else if (streq(p[0], "server-bridge") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->server_bridge_proxy_dhcp = true;
    }
    else if (streq(p[0], "push") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_PUSH);
        push_options(options, &p[1], msglevel, &options->gc);
    }
    else if (streq(p[0], "push-reset") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_INSTANCE);
        push_reset(options);
    }
    else if (streq(p[0], "push-remove") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_INSTANCE);
        msg(D_PUSH, "PUSH_REMOVE '%s'", p[1]);
        push_remove_option(options, p[1]);
    }
    else if (streq(p[0], "ifconfig-pool") && p[1] && p[2] && !p[4])
    {
        const int lev = M_WARN;
        bool error = false;
        in_addr_t start, end, netmask = 0;

        VERIFY_PERMISSION(OPT_P_GENERAL);
        start = get_ip_addr(p[1], lev, &error);
        end = get_ip_addr(p[2], lev, &error);
        if (p[3])
        {
            netmask = get_ip_addr(p[3], lev, &error);
        }
        if (error)
        {
            msg(msglevel, "error parsing --ifconfig-pool parameters");
            goto err;
        }
        if (!ifconfig_pool_verify_range(msglevel, start, end))
        {
            goto err;
        }

        options->ifconfig_pool_defined = true;
        options->ifconfig_pool_start = start;
        options->ifconfig_pool_end = end;
        if (netmask)
        {
            options->ifconfig_pool_netmask = netmask;
        }
    }
    else if (streq(p[0], "ifconfig-pool-persist") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->ifconfig_pool_persist_filename = p[1];
        if (p[2])
        {
            options->ifconfig_pool_persist_refresh_freq = positive_atoi(p[2]);
        }
    }
    else if (streq(p[0], "ifconfig-ipv6-pool") && p[1] && !p[2])
    {
        const int lev = M_WARN;
        struct in6_addr network;
        unsigned int netbits = 0;

        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (!get_ipv6_addr(p[1], &network, &netbits, lev ) )
        {
            msg(msglevel, "error parsing --ifconfig-ipv6-pool parameters");
            goto err;
        }
        if (netbits < 64 || netbits > 124)
        {
            msg(msglevel,
                "--ifconfig-ipv6-pool settings: network must be between /64 and /124 (not /%d)",
                netbits);
            goto err;
        }

        options->ifconfig_ipv6_pool_defined = true;
        options->ifconfig_ipv6_pool_base = network;
        options->ifconfig_ipv6_pool_netbits = netbits;
    }
    else if (streq(p[0], "hash-size") && p[1] && p[2] && !p[3])
    {
        int real, virtual;

        VERIFY_PERMISSION(OPT_P_GENERAL);
        real = atoi(p[1]);
        virtual = atoi(p[2]);
        if (real < 1 || virtual < 1)
        {
            msg(msglevel, "--hash-size sizes must be >= 1 (preferably a power of 2)");
            goto err;
        }
        options->real_hash_size = real;
        options->virtual_hash_size = real;
    }
    else if (streq(p[0], "connect-freq") && p[1] && p[2] && !p[3])
    {
        int cf_max, cf_per;

        VERIFY_PERMISSION(OPT_P_GENERAL);
        cf_max = atoi(p[1]);
        cf_per = atoi(p[2]);
        if (cf_max < 0 || cf_per < 0)
        {
            msg(msglevel, "--connect-freq parms must be > 0");
            goto err;
        }
        options->cf_max = cf_max;
        options->cf_per = cf_per;
    }
    else if (streq(p[0], "connect-freq-initial") && p[1] && p[2] && !p[3])
    {
        long cf_max, cf_per;

        VERIFY_PERMISSION(OPT_P_GENERAL);
        char *e1, *e2;
        cf_max = strtol(p[1], &e1, 10);
        cf_per = strtol(p[2], &e2, 10);
        if (cf_max < 0 || cf_per < 0 || *e1 != '\0' || *e2 != '\0')
        {
            msg(msglevel, "--connect-freq-initial parameters must be integers and >= 0");
            goto err;
        }
        options->cf_initial_max = cf_max;
        options->cf_initial_per = cf_per;
    }
    else if (streq(p[0], "max-clients") && p[1] && !p[2])
    {
        int max_clients;

        VERIFY_PERMISSION(OPT_P_GENERAL);
        max_clients = atoi(p[1]);
        if (max_clients < 0)
        {
            msg(msglevel, "--max-clients must be at least 1");
            goto err;
        }
        if (max_clients >= MAX_PEER_ID) /* max peer-id value */
        {
            msg(msglevel, "--max-clients must be less than %d", MAX_PEER_ID);
            goto err;
        }
        options->max_clients = max_clients;
    }
    else if (streq(p[0], "max-routes-per-client") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_INHERIT);
        options->max_routes_per_client = max_int(atoi(p[1]), 1);
    }
    else if (streq(p[0], "client-cert-not-required") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        msg(M_FATAL, "REMOVED OPTION: --client-cert-not-required, use '--verify-client-cert none' instead");
    }
    else if (streq(p[0], "verify-client-cert") && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);

        /* Reset any existing flags */
        options->ssl_flags &= ~SSLF_CLIENT_CERT_OPTIONAL;
        options->ssl_flags &= ~SSLF_CLIENT_CERT_NOT_REQUIRED;
        if (p[1])
        {
            if (streq(p[1], "none"))
            {
                options->ssl_flags |= SSLF_CLIENT_CERT_NOT_REQUIRED;
            }
            else if (streq(p[1], "optional"))
            {
                options->ssl_flags |= SSLF_CLIENT_CERT_OPTIONAL;
            }
            else if (!streq(p[1], "require"))
            {
                msg(msglevel, "parameter to --verify-client-cert must be 'none', 'optional' or 'require'");
                goto err;
            }
        }
    }
    else if (streq(p[0], "username-as-common-name") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->ssl_flags |= SSLF_USERNAME_AS_COMMON_NAME;
    }
    else if (streq(p[0], "auth-user-pass-optional") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->ssl_flags |= SSLF_AUTH_USER_PASS_OPTIONAL;
    }
    else if (streq(p[0], "opt-verify") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        msg(M_INFO, "DEPRECATION: opt-verify is deprecated and will be removed "
            "in OpenVPN 2.7");
        options->ssl_flags |= SSLF_OPT_VERIFY;
    }
    else if (streq(p[0], "auth-user-pass-verify") && p[1])
    {
        VERIFY_PERMISSION(OPT_P_SCRIPT);
        if (!no_more_than_n_args(msglevel, p, 3, NM_QUOTE_HINT))
        {
            goto err;
        }
        if (p[2])
        {
            if (streq(p[2], "via-env"))
            {
                options->auth_user_pass_verify_script_via_file = false;
            }
            else if (streq(p[2], "via-file"))
            {
                options->auth_user_pass_verify_script_via_file = true;
            }
            else
            {
                msg(msglevel, "second parm to --auth-user-pass-verify must be 'via-env' or 'via-file'");
                goto err;
            }
        }
        else
        {
            msg(msglevel, "--auth-user-pass-verify requires a second parameter ('via-env' or 'via-file')");
            goto err;
        }
        set_user_script(options,
                        &options->auth_user_pass_verify_script,
                        p[1], "auth-user-pass-verify", true);
    }
    else if (streq(p[0], "auth-gen-token"))
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->auth_token_generate = true;
        options->auth_token_lifetime = p[1] ? positive_atoi(p[1]) : 0;

        for (int i = 2; i < MAX_PARMS && p[i] != NULL; i++)
        {
            /* the second parameter can be the renewal time */
            if (i == 2 && positive_atoi(p[i]))
            {
                options->auth_token_renewal = positive_atoi(p[i]);
            }
            else if (streq(p[i], "external-auth"))
            {
                options->auth_token_call_auth = true;
            }
            else
            {
                msg(msglevel, "Invalid argument to auth-gen-token: %s (%d)", p[i], i);
            }
        }

    }
    else if (streq(p[0], "auth-gen-token-secret") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_INLINE);
        options->auth_token_secret_file = p[1];
        options->auth_token_secret_file_inline = is_inline;

    }
    else if (streq(p[0], "client-connect") && p[1])
    {
        VERIFY_PERMISSION(OPT_P_SCRIPT);
        if (!no_more_than_n_args(msglevel, p, 2, NM_QUOTE_HINT))
        {
            goto err;
        }
        set_user_script(options, &options->client_connect_script,
                        p[1], "client-connect", true);
    }
    else if (streq(p[0], "client-crresponse") && p[1])
    {
        VERIFY_PERMISSION(OPT_P_SCRIPT);
        if (!no_more_than_n_args(msglevel, p, 2, NM_QUOTE_HINT))
        {
            goto err;
        }
        set_user_script(options, &options->client_crresponse_script,
                        p[1], "client-crresponse", true);
    }
    else if (streq(p[0], "client-disconnect") && p[1])
    {
        VERIFY_PERMISSION(OPT_P_SCRIPT);
        if (!no_more_than_n_args(msglevel, p, 2, NM_QUOTE_HINT))
        {
            goto err;
        }
        set_user_script(options, &options->client_disconnect_script,
                        p[1], "client-disconnect", true);
    }
    else if (streq(p[0], "learn-address") && p[1])
    {
        VERIFY_PERMISSION(OPT_P_SCRIPT);
        if (!no_more_than_n_args(msglevel, p, 2, NM_QUOTE_HINT))
        {
            goto err;
        }
        set_user_script(options, &options->learn_address_script,
                        p[1], "learn-address", true);
    }
    else if (streq(p[0], "tmp-dir") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->tmp_dir = p[1];
    }
    else if (streq(p[0], "client-config-dir") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->client_config_dir = p[1];
    }
    else if (streq(p[0], "ccd-exclusive") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->ccd_exclusive = true;
    }
    else if (streq(p[0], "bcast-buffers") && p[1] && !p[2])
    {
        int n_bcast_buf;

        VERIFY_PERMISSION(OPT_P_GENERAL);
        n_bcast_buf = atoi(p[1]);
        if (n_bcast_buf < 1)
        {
            msg(msglevel, "--bcast-buffers parameter must be > 0");
        }
        options->n_bcast_buf = n_bcast_buf;
    }
    else if (streq(p[0], "tcp-queue-limit") && p[1] && !p[2])
    {
        int tcp_queue_limit;

        VERIFY_PERMISSION(OPT_P_GENERAL);
        tcp_queue_limit = atoi(p[1]);
        if (tcp_queue_limit < 1)
        {
            msg(msglevel, "--tcp-queue-limit parameter must be > 0");
        }
        options->tcp_queue_limit = tcp_queue_limit;
    }
#if PORT_SHARE
    else if (streq(p[0], "port-share") && p[1] && p[2] && !p[4])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->port_share_host = p[1];
        options->port_share_port = p[2];
        options->port_share_journal_dir = p[3];
    }
#endif
    else if (streq(p[0], "client-to-client") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->enable_c2c = true;
    }
    else if (streq(p[0], "duplicate-cn") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->duplicate_cn = true;
    }
    else if (streq(p[0], "iroute") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_INSTANCE);
        option_iroute(options, p[1], p[2], msglevel);
    }
    else if (streq(p[0], "iroute-ipv6") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_INSTANCE);
        option_iroute_ipv6(options, p[1], msglevel);
    }
    else if (streq(p[0], "ifconfig-push") && p[1] && p[2] && !p[4])
    {
        in_addr_t local, remote_netmask;

        VERIFY_PERMISSION(OPT_P_INSTANCE);
        local = getaddr(GETADDR_HOST_ORDER|GETADDR_RESOLVE, p[1], 0, NULL, NULL);
        remote_netmask = getaddr(GETADDR_HOST_ORDER|GETADDR_RESOLVE, p[2], 0, NULL, NULL);
        if (local && remote_netmask)
        {
            options->push_ifconfig_defined = true;
            options->push_ifconfig_local = local;
            options->push_ifconfig_remote_netmask = remote_netmask;
            if (p[3])
            {
                options->push_ifconfig_local_alias = getaddr(GETADDR_HOST_ORDER|GETADDR_RESOLVE, p[3], 0, NULL, NULL);
            }
        }
        else
        {
            msg(msglevel, "cannot parse --ifconfig-push addresses");
            goto err;
        }
    }
    else if (streq(p[0], "ifconfig-push-constraint") && p[1] && p[2] && !p[3])
    {
        in_addr_t network, netmask;

        VERIFY_PERMISSION(OPT_P_GENERAL);
        network = getaddr(GETADDR_HOST_ORDER|GETADDR_RESOLVE, p[1], 0, NULL, NULL);
        netmask = getaddr(GETADDR_HOST_ORDER, p[2], 0, NULL, NULL);
        if (network && netmask)
        {
            options->push_ifconfig_constraint_defined = true;
            options->push_ifconfig_constraint_network = network;
            options->push_ifconfig_constraint_netmask = netmask;
        }
        else
        {
            msg(msglevel, "cannot parse --ifconfig-push-constraint addresses");
            goto err;
        }
    }
    else if (streq(p[0], "ifconfig-ipv6-push") && p[1] && !p[3])
    {
        struct in6_addr local, remote;
        unsigned int netbits;

        VERIFY_PERMISSION(OPT_P_INSTANCE);

        if (!get_ipv6_addr( p[1], &local, &netbits, msglevel ) )
        {
            msg(msglevel, "cannot parse --ifconfig-ipv6-push addresses");
            goto err;
        }

        if (p[2])
        {
            if (!get_ipv6_addr( p[2], &remote, NULL, msglevel ) )
            {
                msg( msglevel, "cannot parse --ifconfig-ipv6-push addresses");
                goto err;
            }
        }
        else
        {
            if (!options->ifconfig_ipv6_local
                || !get_ipv6_addr( options->ifconfig_ipv6_local, &remote,
                                   NULL, msglevel ) )
            {
                msg( msglevel, "second argument to --ifconfig-ipv6-push missing and no global --ifconfig-ipv6 address set");
                goto err;
            }
        }

        options->push_ifconfig_ipv6_defined = true;
        options->push_ifconfig_ipv6_local = local;
        options->push_ifconfig_ipv6_netbits = netbits;
        options->push_ifconfig_ipv6_remote = remote;
        options->push_ifconfig_ipv6_blocked = false;
    }
    else if (streq(p[0], "disable") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_INSTANCE);
        options->disable = true;
    }
    else if (streq(p[0], "tcp-nodelay") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->server_flags |= SF_TCP_NODELAY_HELPER;
    }
    else if (streq(p[0], "stale-routes-check") && p[1] && !p[3])
    {
        int ageing_time, check_interval;

        VERIFY_PERMISSION(OPT_P_GENERAL);
        ageing_time = atoi(p[1]);
        if (p[2])
        {
            check_interval = atoi(p[2]);
        }
        else
        {
            check_interval = ageing_time;
        }

        if (ageing_time < 1 || check_interval < 1)
        {
            msg(msglevel, "--stale-routes-check aging time and check interval must be >= 1");
            goto err;
        }
        options->stale_routes_ageing_time  = ageing_time;
        options->stale_routes_check_interval = check_interval;
    }

    else if (streq(p[0], "client") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->client = true;
    }
    else if (streq(p[0], "pull") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->pull = true;
    }
    else if (streq(p[0], "push-continuation") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_PULL_MODE);
        options->push_continuation = atoi(p[1]);
    }
    else if (streq(p[0], "auth-user-pass") && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_INLINE);
        if (p[1])
        {
            options->auth_user_pass_file = p[1];
            options->auth_user_pass_file_inline = is_inline;
        }
        else
        {
            options->auth_user_pass_file = "stdin";
        }
    }
    else if (streq(p[0], "auth-retry") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        auth_retry_set(msglevel, p[1]);
    }
#ifdef ENABLE_MANAGEMENT
    else if (streq(p[0], "static-challenge") && p[1] && p[2] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->sc_info.challenge_text = p[1];
        if (atoi(p[2]))
        {
            options->sc_info.flags |= SC_ECHO;
        }
    }
#endif
    else if (streq(p[0], "msg-channel") && p[1])
    {
#ifdef _WIN32
        VERIFY_PERMISSION(OPT_P_GENERAL);
        HANDLE process = GetCurrentProcess();
        HANDLE handle = (HANDLE) ((intptr_t) atoll(p[1]));
        if (!DuplicateHandle(process, handle, process, &options->msg_channel, 0,
                             FALSE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS))
        {
            msg(msglevel, "could not duplicate service pipe handle");
            goto err;
        }
        options->route_method = ROUTE_METHOD_SERVICE;
#else  /* ifdef _WIN32 */
        msg(msglevel, "--msg-channel is only supported on Windows");
        goto err;
#endif
    }
#ifdef _WIN32
    else if (streq(p[0], "win-sys") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (streq(p[1], "env"))
        {
            msg(M_INFO, "NOTE: --win-sys env is default from OpenVPN 2.3.	 "
                "This entry will now be ignored.  "
                "Please remove this entry from your configuration file.");
        }
        else
        {
            set_win_sys_path(p[1], es);
        }
    }
    else if (streq(p[0], "route-method") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_ROUTE_EXTRAS);
        if (streq(p[1], "adaptive"))
        {
            options->route_method = ROUTE_METHOD_ADAPTIVE;
        }
        else if (streq(p[1], "ipapi"))
        {
            options->route_method = ROUTE_METHOD_IPAPI;
        }
        else if (streq(p[1], "exe"))
        {
            options->route_method = ROUTE_METHOD_EXE;
        }
        else
        {
            msg(msglevel, "--route method must be 'adaptive', 'ipapi', or 'exe'");
            goto err;
        }
    }
    else if (streq(p[0], "ip-win32") && p[1] && !p[4])
    {
        const int index = ascii2ipset(p[1]);
        struct tuntap_options *to = &options->tuntap_options;

        VERIFY_PERMISSION(OPT_P_DHCPDNS);

        if (index < 0)
        {
            msg(msglevel,
                "Bad --ip-win32 method: '%s'.  Allowed methods: %s",
                p[1],
                ipset2ascii_all(&gc));
            goto err;
        }

        if (index == IPW32_SET_ADAPTIVE)
        {
            options->route_delay_window = IPW32_SET_ADAPTIVE_DELAY_WINDOW;
        }

        if (index == IPW32_SET_DHCP_MASQ)
        {
            if (p[2])
            {
                if (!streq(p[2], "default"))
                {
                    int offset = atoi(p[2]);

                    if (!(offset > -256 && offset < 256))
                    {
                        msg(msglevel, "--ip-win32 dynamic [offset] [lease-time]: offset (%d) must be > -256 and < 256", offset);
                        goto err;
                    }

                    to->dhcp_masq_custom_offset = true;
                    to->dhcp_masq_offset = offset;
                }

                if (p[3])
                {
                    const int min_lease = 30;
                    int lease_time;
                    lease_time = atoi(p[3]);
                    if (lease_time < min_lease)
                    {
                        msg(msglevel, "--ip-win32 dynamic [offset] [lease-time]: lease time parameter (%d) must be at least %d seconds", lease_time, min_lease);
                        goto err;
                    }
                    to->dhcp_lease_time = lease_time;
                }
            }
        }
        to->ip_win32_type = index;
        to->ip_win32_defined = true;
    }
#endif /* ifdef _WIN32 */
    else if (streq(p[0], "dns") && p[1])
    {
        VERIFY_PERMISSION(OPT_P_DHCPDNS);

        if (streq(p[1], "search-domains") && p[2])
        {
            dns_domain_list_append(&options->dns_options.search_domains, &p[2], &options->dns_options.gc);
        }
        else if (streq(p[1], "server") && p[2] && p[3] && p[4])
        {
            long priority;
            if (!dns_server_priority_parse(&priority, p[2], pull_mode))
            {
                msg(msglevel, "--dns server: invalid priority value '%s'", p[2]);
                goto err;
            }

            struct dns_server *server = dns_server_get(&options->dns_options.servers, priority, &options->dns_options.gc);

            if (streq(p[3], "address") && p[4])
            {
                for (int i = 4; p[i]; ++i)
                {
                    if (!dns_server_addr_parse(server, p[i]))
                    {
                        msg(msglevel, "--dns server %ld: malformed address or maximum exceeded '%s'", priority, p[i]);
                        goto err;
                    }
                }
            }
            else if (streq(p[3], "resolve-domains"))
            {
                dns_domain_list_append(&server->domains, &p[4], &options->dns_options.gc);
            }
            else if (streq(p[3], "dnssec") && !p[5])
            {
                if (streq(p[4], "yes"))
                {
                    server->dnssec = DNS_SECURITY_YES;
                }
                else if (streq(p[4], "no"))
                {
                    server->dnssec = DNS_SECURITY_NO;
                }
                else if (streq(p[4], "optional"))
                {
                    server->dnssec = DNS_SECURITY_OPTIONAL;
                }
                else
                {
                    msg(msglevel, "--dns server %ld: malformed dnssec value '%s'", priority, p[4]);
                    goto err;
                }
            }
            else if (streq(p[3], "transport") && !p[5])
            {
                if (streq(p[4], "plain"))
                {
                    server->transport = DNS_TRANSPORT_PLAIN;
                }
                else if (streq(p[4], "DoH"))
                {
                    server->transport = DNS_TRANSPORT_HTTPS;
                }
                else if (streq(p[4], "DoT"))
                {
                    server->transport = DNS_TRANSPORT_TLS;
                }
                else
                {
                    msg(msglevel, "--dns server %ld: malformed transport value '%s'", priority, p[4]);
                    goto err;
                }
            }
            else if (streq(p[3], "sni") && !p[5])
            {
                server->sni = p[4];
            }
            else
            {
                msg(msglevel, "--dns server %ld: unknown option type '%s' or missing or unknown parameter", priority, p[3]);
                goto err;
            }
        }
        else
        {
            msg(msglevel, "--dns: unknown option type '%s' or missing or unknown parameter", p[1]);
            goto err;
        }
    }
#if defined(_WIN32) || defined(TARGET_ANDROID)
    else if (streq(p[0], "dhcp-option") && p[1])
    {
        struct tuntap_options *o = &options->tuntap_options;
        VERIFY_PERMISSION(OPT_P_DHCPDNS);

        if ((streq(p[1], "DOMAIN") || streq(p[1], "ADAPTER_DOMAIN_SUFFIX"))
            && p[2] && !p[3])
        {
            o->domain = p[2];
            o->dhcp_options |= DHCP_OPTIONS_DHCP_OPTIONAL;
        }
        else if (streq(p[1], "NBS") && p[2] && !p[3])
        {
            o->netbios_scope = p[2];
            o->dhcp_options |= DHCP_OPTIONS_DHCP_REQUIRED;
        }
        else if (streq(p[1], "NBT") && p[2] && !p[3])
        {
            int t;
            t = atoi(p[2]);
            if (!(t == 1 || t == 2 || t == 4 || t == 8))
            {
                msg(msglevel, "--dhcp-option NBT: parameter (%d) must be 1, 2, 4, or 8", t);
                goto err;
            }
            o->netbios_node_type = t;
            o->dhcp_options |= DHCP_OPTIONS_DHCP_REQUIRED;
        }
        else if ((streq(p[1], "DNS") || streq(p[1], "DNS6")) && p[2] && !p[3]
                 && (!strstr(p[2], ":") || ipv6_addr_safe(p[2])))
        {
            if (strstr(p[2], ":"))
            {
                dhcp_option_dns6_parse(p[2], o->dns6, &o->dns6_len, msglevel);
            }
            else
            {
                dhcp_option_address_parse("DNS", p[2], o->dns, &o->dns_len, msglevel);
                o->dhcp_options |= DHCP_OPTIONS_DHCP_OPTIONAL;
            }
        }
        else if (streq(p[1], "WINS") && p[2] && !p[3])
        {
            dhcp_option_address_parse("WINS", p[2], o->wins, &o->wins_len, msglevel);
            o->dhcp_options |= DHCP_OPTIONS_DHCP_OPTIONAL;
        }
        else if (streq(p[1], "NTP") && p[2] && !p[3])
        {
            dhcp_option_address_parse("NTP", p[2], o->ntp, &o->ntp_len, msglevel);
            o->dhcp_options |= DHCP_OPTIONS_DHCP_REQUIRED;
        }
        else if (streq(p[1], "NBDD") && p[2] && !p[3])
        {
            dhcp_option_address_parse("NBDD", p[2], o->nbdd, &o->nbdd_len, msglevel);
            o->dhcp_options |= DHCP_OPTIONS_DHCP_REQUIRED;
        }
        else if (streq(p[1], "DOMAIN-SEARCH") && p[2] && !p[3])
        {
            if (o->domain_search_list_len < N_SEARCH_LIST_LEN)
            {
                o->domain_search_list[o->domain_search_list_len++] = p[2];
            }
            else
            {
                msg(msglevel, "--dhcp-option %s: maximum of %d search entries can be specified",
                    p[1], N_SEARCH_LIST_LEN);
            }
            o->dhcp_options |= DHCP_OPTIONS_DHCP_REQUIRED;
        }
        else if (streq(p[1], "DISABLE-NBT") && !p[2])
        {
            o->disable_nbt = 1;
            o->dhcp_options |= DHCP_OPTIONS_DHCP_REQUIRED;
        }
#if defined(TARGET_ANDROID)
        else if (streq(p[1], "PROXY_HTTP") && p[3] && !p[4])
        {
            o->http_proxy_port = atoi(p[3]);
            o->http_proxy = p[2];
        }
#endif
        else
        {
            msg(msglevel, "--dhcp-option: unknown option type '%s' or missing or unknown parameter", p[1]);
            goto err;
        }
    }
#endif /* if defined(_WIN32) || defined(TARGET_ANDROID) */
#ifdef _WIN32
    else if (streq(p[0], "show-adapters") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        show_tap_win_adapters(M_INFO|M_NOPREFIX, M_WARN|M_NOPREFIX);
        openvpn_exit(OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }
    else if (streq(p[0], "show-net") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        show_routes(M_INFO|M_NOPREFIX);
        show_adapters(M_INFO|M_NOPREFIX);
        openvpn_exit(OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }
    else if (streq(p[0], "show-net-up") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_UP);
        options->show_net_up = true;
    }
    else if (streq(p[0], "tap-sleep") && p[1] && !p[2])
    {
        int s;
        VERIFY_PERMISSION(OPT_P_DHCPDNS);
        s = atoi(p[1]);
        if (s < 0 || s >= 256)
        {
            msg(msglevel, "--tap-sleep parameter must be between 0 and 255");
            goto err;
        }
        options->tuntap_options.tap_sleep = s;
    }
    else if (streq(p[0], "dhcp-renew") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_DHCPDNS);
        options->tuntap_options.dhcp_renew = true;
    }
    else if (streq(p[0], "dhcp-pre-release") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_DHCPDNS);
        options->tuntap_options.dhcp_pre_release = true;
        options->tuntap_options.dhcp_renew = true;
    }
    else if (streq(p[0], "dhcp-release") && !p[1])
    {
        msg(M_WARN, "Obsolete option --dhcp-release detected. This is now on by default");
    }
    else if (streq(p[0], "dhcp-internal") && p[1] && !p[2]) /* standalone method for internal use */
    {
        unsigned int adapter_index;
        VERIFY_PERMISSION(OPT_P_GENERAL);
        set_debug_level(options->verbosity, SDL_CONSTRAIN);
        adapter_index = atou(p[1]);
        sleep(options->tuntap_options.tap_sleep);
        if (options->tuntap_options.dhcp_pre_release)
        {
            dhcp_release_by_adapter_index(adapter_index);
        }
        if (options->tuntap_options.dhcp_renew)
        {
            dhcp_renew_by_adapter_index(adapter_index);
        }
        openvpn_exit(OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }
    else if (streq(p[0], "register-dns") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_DHCPDNS);
        options->tuntap_options.register_dns = true;
    }
    else if (streq(p[0], "block-outside-dns") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_DHCPDNS);
        options->block_outside_dns = true;
    }
    else if (streq(p[0], "rdns-internal") && !p[1])
    /* standalone method for internal use
     *
     * (if --register-dns is set, openvpn needs to call itself in a
     *  sub-process to execute the required functions in a non-blocking
     *  way, and uses --rdns-internal to signal that to itself)
     */
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        set_debug_level(options->verbosity, SDL_CONSTRAIN);
        if (options->tuntap_options.register_dns)
        {
            ipconfig_register_dns(NULL);
        }
        openvpn_exit(OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }
    else if (streq(p[0], "show-valid-subnets") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        show_valid_win32_tun_subnets();
        openvpn_exit(OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }
    else if (streq(p[0], "pause-exit") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        set_pause_exit_win32();
    }
    else if (streq(p[0], "service") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->exit_event_name = p[1];
        if (p[2])
        {
            options->exit_event_initial_state = (atoi(p[2]) != 0);
        }
    }
    else if (streq(p[0], "allow-nonadmin") && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        tap_allow_nonadmin_access(p[1]);
        openvpn_exit(OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }
    else if (streq(p[0], "user") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        msg(M_WARN, "NOTE: --user option is not implemented on Windows");
    }
    else if (streq(p[0], "group") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        msg(M_WARN, "NOTE: --group option is not implemented on Windows");
    }
#else  /* ifdef _WIN32 */
    else if (streq(p[0], "user") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->username = p[1];
    }
    else if (streq(p[0], "group") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->groupname = p[1];
    }
    else if (streq(p[0], "dhcp-option") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_DHCPDNS);
        setenv_foreign_option(options, (const char **)p, 3, es);
    }
    else if (streq(p[0], "route-method") && p[1] && !p[2]) /* ignore when pushed to non-Windows OS */
    {
        VERIFY_PERMISSION(OPT_P_ROUTE_EXTRAS);
    }
#endif /* ifdef _WIN32 */
#if PASSTOS_CAPABILITY
    else if (streq(p[0], "passtos") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->passtos = true;
    }
#endif
    else if (streq(p[0], "allow-compression") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);

        if (streq(p[1], "no"))
        {
            options->comp.flags =
                COMP_F_ALLOW_STUB_ONLY|COMP_F_ADVERTISE_STUBS_ONLY;
            if (comp_non_stub_enabled(&options->comp))
            {
                msg(msglevel, "'--allow-compression no' conflicts with "
                    " enabling compression");
            }
        }
        else if (options->comp.flags & COMP_F_ALLOW_STUB_ONLY)
        {
            /* Also printed on a push to hint at configuration problems */
            msg(msglevel, "Cannot set allow-compression to '%s' "
                "after set to 'no'", p[1]);
            goto err;
        }
        else if (streq(p[1], "asym"))
        {
            options->comp.flags &= ~COMP_F_ALLOW_COMPRESS;
            options->comp.flags |= COMP_F_ALLOW_ASYM;
        }
        else if (streq(p[1], "yes"))
        {
            msg(M_WARN, "WARNING: Compression for sending and receiving enabled. Compression has "
                "been used in the past to break encryption. Allowing compression allows "
                "attacks that break encryption. Using \"--allow-compression yes\" is "
                "strongly discouraged for common usage. See --compress in the manual "
                "page for more information ");

            options->comp.flags |= COMP_F_ALLOW_COMPRESS;
        }
        else
        {
            msg(msglevel, "bad allow-compression option: %s -- "
                "must be 'yes', 'no', or 'asym'", p[1]);
            goto err;
        }
    }
    else if (streq(p[0], "comp-lzo") && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_COMP);

        /* All lzo variants do not use swap */
        options->comp.flags &= ~COMP_F_SWAP;

        if (p[1] && streq(p[1], "no"))
        {
            options->comp.alg = COMP_ALG_STUB;
            options->comp.flags &= ~COMP_F_ADAPTIVE;
        }
        else if (p[1])
        {
            if (streq(p[1], "yes"))
            {
                options->comp.alg = COMP_ALG_LZO;
                options->comp.flags &= ~COMP_F_ADAPTIVE;
            }
            else if (streq(p[1], "adaptive"))
            {
                options->comp.alg = COMP_ALG_LZO;
                options->comp.flags |= COMP_F_ADAPTIVE;
            }
            else
            {
                msg(msglevel, "bad comp-lzo option: %s -- must be 'yes', 'no', or 'adaptive'", p[1]);
                goto err;
            }
        }
        else
        {
            options->comp.alg = COMP_ALG_LZO;
            options->comp.flags |= COMP_F_ADAPTIVE;
        }
        show_compression_warning(&options->comp);
    }
    else if (streq(p[0], "comp-noadapt") && !p[1])
    {
        /*
         * We do not need to check here if we allow compression since
         * it only modifies a flag if compression is enabled
         */
        VERIFY_PERMISSION(OPT_P_COMP);
        options->comp.flags &= ~COMP_F_ADAPTIVE;
    }
    else if (streq(p[0], "compress") && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_COMP);
        const char *alg = "stub";
        if (p[1])
        {
            alg = p[1];
        }

        if (streq(alg, "stub"))
        {
            options->comp.alg = COMP_ALG_STUB;
            options->comp.flags |= (COMP_F_SWAP|COMP_F_ADVERTISE_STUBS_ONLY);
        }
        else if (streq(alg, "stub-v2"))
        {
            options->comp.alg = COMP_ALGV2_UNCOMPRESSED;
            options->comp.flags |= COMP_F_ADVERTISE_STUBS_ONLY;
        }
        else if (streq(alg, "migrate"))
        {
            options->comp.alg = COMP_ALG_UNDEF;
            options->comp.flags = COMP_F_MIGRATE;
        }
        else if (streq(alg, "lzo"))
        {
            options->comp.alg = COMP_ALG_LZO;
            options->comp.flags &= ~(COMP_F_ADAPTIVE | COMP_F_SWAP);
        }
        else if (streq(alg, "lz4"))
        {
            options->comp.alg = COMP_ALG_LZ4;
            options->comp.flags |= COMP_F_SWAP;
        }
        else if (streq(alg, "lz4-v2"))
        {
            options->comp.alg = COMP_ALGV2_LZ4;
        }
        else
        {
            msg(msglevel, "bad comp option: %s", alg);
            goto err;
        }

        show_compression_warning(&options->comp);
    }
    else if (streq(p[0], "show-ciphers") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->show_ciphers = true;
    }
    else if (streq(p[0], "show-digests") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->show_digests = true;
    }
    else if (streq(p[0], "show-engines") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->show_engines = true;
    }
    else if (streq(p[0], "key-direction") && p[1] && !p[2])
    {
        int key_direction;

        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);

        key_direction = ascii2keydirection(msglevel, p[1]);
        if (key_direction >= 0)
        {
            if (permission_mask & OPT_P_GENERAL)
            {
                options->key_direction = key_direction;
            }
            else if (permission_mask & OPT_P_CONNECTION)
            {
                options->ce.key_direction = key_direction;
            }
        }
        else
        {
            goto err;
        }
    }
    else if (streq(p[0], "secret") && p[1] && !p[3])
    {
        msg(M_WARN, "DEPRECATED OPTION: The option --secret is deprecated.");
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_INLINE);
        options->shared_secret_file = p[1];
        options->shared_secret_file_inline = is_inline;
        if (!is_inline && p[2])
        {
            int key_direction;

            key_direction = ascii2keydirection(msglevel, p[2]);
            if (key_direction >= 0)
            {
                options->key_direction = key_direction;
            }
            else
            {
                goto err;
            }
        }
    }
    else if (streq(p[0], "genkey") && !p[4])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->genkey = true;
        if (!p[1])
        {
            options->genkey_type = GENKEY_SECRET;
        }
        else
        {
            if (streq(p[1], "secret") || streq(p[1], "tls-auth")
                || streq(p[1], "tls-crypt"))
            {
                options->genkey_type = GENKEY_SECRET;
            }
            else if (streq(p[1], "tls-crypt-v2-server"))
            {
                options->genkey_type = GENKEY_TLS_CRYPTV2_SERVER;
            }
            else if (streq(p[1], "tls-crypt-v2-client"))
            {
                options->genkey_type = GENKEY_TLS_CRYPTV2_CLIENT;
                if (p[3])
                {
                    options->genkey_extra_data = p[3];
                }
            }
            else if (streq(p[1], "auth-token"))
            {
                options->genkey_type = GENKEY_AUTH_TOKEN;
            }
            else
            {
                msg(msglevel, "unknown --genkey type: %s", p[1]);
            }

        }
        if (p[2])
        {
            options->genkey_filename = p[2];
        }
    }
    else if (streq(p[0], "auth") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->authname = p[1];
    }
    else if (streq(p[0], "cipher") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_NCP|OPT_P_INSTANCE);
        options->ciphername = p[1];
    }
    else if (streq(p[0], "data-ciphers-fallback") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_INSTANCE);
        options->ciphername = p[1];
        options->enable_ncp_fallback = true;
    }
    else if ((streq(p[0], "data-ciphers") || streq(p[0], "ncp-ciphers"))
             && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_INSTANCE);
        if (streq(p[0], "ncp-ciphers"))
        {
            msg(M_INFO, "Note: Treating option '--ncp-ciphers' as "
                " '--data-ciphers' (renamed in OpenVPN 2.5).");
        }
        options->ncp_ciphers = p[1];
    }
    else if (streq(p[0], "key-derivation") && p[1])
    {
        /* NCP only option that is pushed by the server to enable EKM,
         * should not be used by normal users in config files*/
        VERIFY_PERMISSION(OPT_P_NCP)
#ifdef HAVE_EXPORT_KEYING_MATERIAL
        if (streq(p[1], "tls-ekm"))
        {
            options->imported_protocol_flags |= CO_USE_TLS_KEY_MATERIAL_EXPORT;
        }
        else
#endif
        {
            msg(msglevel, "Unknown key-derivation method %s", p[1]);
        }
    }
    else if (streq(p[0], "protocol-flags") && p[1])
    {
        /* NCP only option that is pushed by the server to enable protocol
         * features that are negotiated, should not be used by normal users
         * in config files */
        VERIFY_PERMISSION(OPT_P_NCP)
        for (size_t j = 1; j < MAX_PARMS && p[j] != NULL; j++)
        {
            if (streq(p[j], "cc-exit"))
            {
                options->imported_protocol_flags |= CO_USE_CC_EXIT_NOTIFY;
            }
#ifdef HAVE_EXPORT_KEYING_MATERIAL
            else if (streq(p[j], "tls-ekm"))
            {
                options->imported_protocol_flags |= CO_USE_TLS_KEY_MATERIAL_EXPORT;
            }
            else if (streq(p[j], "dyn-tls-crypt"))
            {
                options->imported_protocol_flags |= CO_USE_DYNAMIC_TLS_CRYPT;
            }
#endif
            else
            {
                msg(msglevel, "Unknown protocol-flags flag: %s", p[j]);
            }
        }
    }
    else if (streq(p[0], "force-tls-key-material-export"))
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->force_key_material_export = true;
    }
    else if (streq(p[0], "prng") && p[1] && !p[3])
    {
        msg(M_WARN, "NOTICE: --prng option ignored (SSL library PRNG is used)");
    }
    else if (streq(p[0], "no-replay") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->replay = false;
    }
    else if (streq(p[0], "replay-window") && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (p[1])
        {
            int replay_window;

            replay_window = atoi(p[1]);
            if (!(MIN_SEQ_BACKTRACK <= replay_window && replay_window <= MAX_SEQ_BACKTRACK))
            {
                msg(msglevel, "replay-window window size parameter (%d) must be between %d and %d",
                    replay_window,
                    MIN_SEQ_BACKTRACK,
                    MAX_SEQ_BACKTRACK);
                goto err;
            }
            options->replay_window = replay_window;

            if (p[2])
            {
                int replay_time;

                replay_time = atoi(p[2]);
                if (!(MIN_TIME_BACKTRACK <= replay_time && replay_time <= MAX_TIME_BACKTRACK))
                {
                    msg(msglevel, "replay-window time window parameter (%d) must be between %d and %d",
                        replay_time,
                        MIN_TIME_BACKTRACK,
                        MAX_TIME_BACKTRACK);
                    goto err;
                }
                options->replay_time = replay_time;
            }
        }
        else
        {
            msg(msglevel, "replay-window option is missing window size parameter");
            goto err;
        }
    }
    else if (streq(p[0], "mute-replay-warnings") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->mute_replay_warnings = true;
    }
    else if (streq(p[0], "replay-persist") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->packet_id_file = p[1];
    }
    else if (streq(p[0], "test-crypto") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->test_crypto = true;
    }
#ifndef ENABLE_CRYPTO_MBEDTLS
    else if (streq(p[0], "engine") && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (p[1])
        {
            options->engine = p[1];
        }
        else
        {
            options->engine = "auto";
        }
    }
#endif /* ENABLE_CRYPTO_MBEDTLS */
    else if (streq(p[0], "providers") && p[1])
    {
        for (size_t j = 1; j < MAX_PARMS && p[j] != NULL; j++)
        {
            options->providers.names[j] = p[j];
        }
    }
#ifdef ENABLE_PREDICTION_RESISTANCE
    else if (streq(p[0], "use-prediction-resistance") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->use_prediction_resistance = true;
    }
#endif
    else if (streq(p[0], "show-tls") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->show_tls_ciphers = true;
    }
    else if ((streq(p[0], "show-curves") || streq(p[0], "show-groups")) && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->show_curves = true;
    }
    else if (streq(p[0], "ecdh-curve") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        msg(M_WARN, "Consider setting groups/curves preference with "
            "tls-groups instead of forcing a specific curve with "
            "ecdh-curve.");
        options->ecdh_curve = p[1];
    }
    else if (streq(p[0], "tls-server") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->tls_server = true;
    }
    else if (streq(p[0], "tls-client") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->tls_client = true;
    }
    else if (streq(p[0], "ca") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_INLINE);
        options->ca_file = p[1];
        options->ca_file_inline = is_inline;
    }
#ifndef ENABLE_CRYPTO_MBEDTLS
    else if (streq(p[0], "capath") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->ca_path = p[1];
    }
#endif /* ENABLE_CRYPTO_MBEDTLS */
    else if (streq(p[0], "dh") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_INLINE);
        options->dh_file = p[1];
        options->dh_file_inline = is_inline;
    }
    else if (streq(p[0], "cert") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_INLINE);
        options->cert_file = p[1];
        options->cert_file_inline = is_inline;
    }
    else if (streq(p[0], "extra-certs") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_INLINE);
        options->extra_certs_file = p[1];
        options->extra_certs_file_inline = is_inline;
    }
    else if ((streq(p[0], "verify-hash") && p[1] && !p[3])
             || (streq(p[0], "peer-fingerprint") && p[1] && !p[2]))
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_INLINE);

        int verify_hash_depth = 0;
        if (streq(p[0], "verify-hash"))
        {
            msg(M_WARN, "DEPRECATED OPTION: The option --verify-hash is deprecated. "
                "You should switch to the either use the level 1 certificate as "
                "--ca option, use --tls-verify or use --peer-fingerprint");
            /* verify level 1 cert, i.e. the CA that signed the leaf cert */
            verify_hash_depth = 1;
        }

        options->verify_hash_algo = MD_SHA256;

        int digest_len = SHA256_DIGEST_LENGTH;

        if (options->verify_hash && options->verify_hash_depth != verify_hash_depth)
        {
            msg(msglevel, "ERROR: Setting %s not allowed. --verify-hash and"
                " --peer-fingerprint are mutually exclusive", p[0]);
            goto err;
        }

        if (streq(p[0], "verify-hash"))
        {
            if ((!p[2] && !is_inline) || (p[2] && streq(p[2], "SHA1")))
            {
                options->verify_hash_algo = MD_SHA1;
                digest_len = SHA_DIGEST_LENGTH;
            }
            else if (p[2] && !streq(p[2], "SHA256"))
            {
                msg(msglevel, "invalid or unsupported hashing algorithm: %s "
                    "(only SHA1 and SHA256 are supported)", p[2]);
                goto err;
            }
        }

        struct verify_hash_list *newlist;
        newlist = parse_hash_fingerprint_multiline(p[1], digest_len,
                                                   msglevel, &options->gc);

        /* Append the new list to the end of our current list */
        if (!options->verify_hash)
        {
            options->verify_hash = newlist;
            options->verify_hash_depth = verify_hash_depth;
        }
        else
        {
            /* since both the old and new list can have multiple entries
             * we need to go to the end of one of them to concatenate them  */
            struct verify_hash_list *listend = options->verify_hash;
            while (listend->next)
            {
                listend = listend->next;
            }
            listend->next = newlist;
        }
    }
#if defined(ENABLE_CRYPTOAPI) && defined(HAVE_XKEY_PROVIDER)
    else if (streq(p[0], "cryptoapicert") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->cryptoapi_cert = p[1];
    }
#endif
    else if (streq(p[0], "key") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_INLINE);
        options->priv_key_file = p[1];
        options->priv_key_file_inline = is_inline;
    }
    else if (streq(p[0], "tls-version-min") && p[1] && !p[3])
    {
        int ver;
        VERIFY_PERMISSION(OPT_P_GENERAL);
        ver = tls_version_parse(p[1], p[2]);
        if (ver == TLS_VER_BAD)
        {
            msg(msglevel, "unknown tls-version-min parameter: %s", p[1]);
            goto err;
        }
        options->ssl_flags &=
            ~(SSLF_TLS_VERSION_MIN_MASK << SSLF_TLS_VERSION_MIN_SHIFT);
        options->ssl_flags |= (ver << SSLF_TLS_VERSION_MIN_SHIFT);
    }
    else if (streq(p[0], "tls-version-max") && p[1] && !p[2])
    {
        int ver;
        VERIFY_PERMISSION(OPT_P_GENERAL);
        ver = tls_version_parse(p[1], NULL);
        if (ver == TLS_VER_BAD)
        {
            msg(msglevel, "unknown tls-version-max parameter: %s", p[1]);
            goto err;
        }
        options->ssl_flags &=
            ~(SSLF_TLS_VERSION_MAX_MASK << SSLF_TLS_VERSION_MAX_SHIFT);
        options->ssl_flags |= (ver << SSLF_TLS_VERSION_MAX_SHIFT);
    }
#ifndef ENABLE_CRYPTO_MBEDTLS
    else if (streq(p[0], "pkcs12") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_INLINE);
        options->pkcs12_file = p[1];
        options->pkcs12_file_inline = is_inline;
    }
#endif /* ENABLE_CRYPTO_MBEDTLS */
    else if (streq(p[0], "askpass") && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (p[1])
        {
            options->key_pass_file = p[1];
        }
        else
        {
            options->key_pass_file = "stdin";
        }
    }
    else if (streq(p[0], "auth-nocache") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        ssl_set_auth_nocache();
    }
    else if (streq(p[0], "auth-token") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_ECHO);
        ssl_set_auth_token(p[1]);
#ifdef ENABLE_MANAGEMENT
        if (management)
        {
            management_auth_token(management, p[1]);
        }
#endif
    }
    else if (streq(p[0], "auth-token-user") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_ECHO);
        ssl_set_auth_token_user(p[1]);
    }
    else if (streq(p[0], "single-session") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->single_session = true;
    }
    else if (streq(p[0], "push-peer-info") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->push_peer_info = true;
    }
    else if (streq(p[0], "tls-exit") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->tls_exit = true;
    }
    else if (streq(p[0], "tls-cipher") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->cipher_list = p[1];
    }
    else if (streq(p[0], "tls-cert-profile") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->tls_cert_profile = p[1];
    }
    else if (streq(p[0], "tls-ciphersuites") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->cipher_list_tls13 = p[1];
    }
    else if (streq(p[0], "tls-groups") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->tls_groups = p[1];
    }
    else if (streq(p[0], "crl-verify") && p[1] && ((p[2] && streq(p[2], "dir"))
                                                   || !p[2]))
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_INLINE);
        if (p[2] && streq(p[2], "dir"))
        {
            options->ssl_flags |= SSLF_CRL_VERIFY_DIR;
        }
        options->crl_file = p[1];
        options->crl_file_inline = is_inline;
    }
    else if (streq(p[0], "tls-verify") && p[1])
    {
        VERIFY_PERMISSION(OPT_P_SCRIPT);
        if (!no_more_than_n_args(msglevel, p, 2, NM_QUOTE_HINT))
        {
            goto err;
        }
        set_user_script(options, &options->tls_verify,
                        string_substitute(p[1], ',', ' ', &options->gc),
                        "tls-verify", true);
    }
    else if (streq(p[0], "tls-export-cert") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_SCRIPT);
        options->tls_export_peer_cert_dir = p[1];
    }
    else if (streq(p[0], "compat-names"))
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        msg(msglevel, "--compat-names was removed in OpenVPN 2.5. "
            "Update your configuration.");
        goto err;
    }
    else if (streq(p[0], "no-name-remapping") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        msg(msglevel, "--no-name-remapping was removed in OpenVPN 2.5. "
            "Update your configuration.");
        goto err;
    }
    else if (streq(p[0], "verify-x509-name") && p[1] && strlen(p[1]) && !p[3])
    {
        int type = VERIFY_X509_SUBJECT_DN;
        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (p[2])
        {
            if (streq(p[2], "subject"))
            {
                type = VERIFY_X509_SUBJECT_DN;
            }
            else if (streq(p[2], "name"))
            {
                type = VERIFY_X509_SUBJECT_RDN;
            }
            else if (streq(p[2], "name-prefix"))
            {
                type = VERIFY_X509_SUBJECT_RDN_PREFIX;
            }
            else
            {
                msg(msglevel, "unknown X.509 name type: %s", p[2]);
                goto err;
            }
        }
        options->verify_x509_type = type;
        options->verify_x509_name = p[1];
    }
    else if (streq(p[0], "ns-cert-type") && p[1] && !p[2])
    {
#ifdef ENABLE_CRYPTO_MBEDTLS
        msg(msglevel, "--ns-cert-type is not available with mbedtls.");
        goto err;
#else
        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (streq(p[1], "server"))
        {
            options->ns_cert_type = NS_CERT_CHECK_SERVER;
        }
        else if (streq(p[1], "client"))
        {
            options->ns_cert_type = NS_CERT_CHECK_CLIENT;
        }
        else
        {
            msg(msglevel, "--ns-cert-type must be 'client' or 'server'");
            goto err;
        }
#endif /* ENABLE_CRYPTO_MBEDTLS */
    }
    else if (streq(p[0], "remote-cert-ku"))
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);

        size_t j;
        for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j)
        {
            sscanf(p[j], "%x", &(options->remote_cert_ku[j-1]));
        }
        if (j == 1)
        {
            /* No specific KU required, but require KU to be present */
            options->remote_cert_ku[0] = OPENVPN_KU_REQUIRED;
        }
    }
    else if (streq(p[0], "remote-cert-eku") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->remote_cert_eku = p[1];
    }
    else if (streq(p[0], "remote-cert-tls") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);

        if (streq(p[1], "server"))
        {
            options->remote_cert_ku[0] = OPENVPN_KU_REQUIRED;
            options->remote_cert_eku = "TLS Web Server Authentication";
        }
        else if (streq(p[1], "client"))
        {
            options->remote_cert_ku[0] = OPENVPN_KU_REQUIRED;
            options->remote_cert_eku = "TLS Web Client Authentication";
        }
        else
        {
            msg(msglevel, "--remote-cert-tls must be 'client' or 'server'");
            goto err;
        }
    }
    else if (streq(p[0], "tls-timeout") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_TLS_PARMS);
        options->tls_timeout = positive_atoi(p[1]);
    }
    else if (streq(p[0], "reneg-bytes") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_TLS_PARMS);
        options->renegotiate_bytes = positive_atoi(p[1]);
    }
    else if (streq(p[0], "reneg-pkts") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_TLS_PARMS);
        options->renegotiate_packets = positive_atoi(p[1]);
    }
    else if (streq(p[0], "reneg-sec") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_TLS_PARMS);
        options->renegotiate_seconds = positive_atoi(p[1]);
        if (p[2])
        {
            options->renegotiate_seconds_min = positive_atoi(p[2]);
        }
    }
    else if (streq(p[0], "hand-window") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_TLS_PARMS);
        options->handshake_window = positive_atoi(p[1]);
    }
    else if (streq(p[0], "tran-window") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_TLS_PARMS);
        options->transition_window = positive_atoi(p[1]);
    }
    else if (streq(p[0], "tls-auth") && p[1] && !p[3])
    {
        int key_direction = -1;

        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION|OPT_P_INLINE);

        if (permission_mask & OPT_P_GENERAL)
        {
            options->tls_auth_file = p[1];
            options->tls_auth_file_inline = is_inline;

            if (!is_inline && p[2])
            {
                key_direction = ascii2keydirection(msglevel, p[2]);
                if (key_direction < 0)
                {
                    goto err;
                }
                options->key_direction = key_direction;
            }

        }
        else if (permission_mask & OPT_P_CONNECTION)
        {
            options->ce.tls_auth_file = p[1];
            options->ce.tls_auth_file_inline = is_inline;
            options->ce.key_direction = KEY_DIRECTION_BIDIRECTIONAL;

            if (!is_inline && p[2])
            {
                key_direction = ascii2keydirection(msglevel, p[2]);
                if (key_direction < 0)
                {
                    goto err;
                }
                options->ce.key_direction = key_direction;
            }
        }
    }
    else if (streq(p[0], "tls-crypt") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION|OPT_P_INLINE);
        if (permission_mask & OPT_P_GENERAL)
        {
            options->tls_crypt_file = p[1];
            options->tls_crypt_file_inline = is_inline;
        }
        else if (permission_mask & OPT_P_CONNECTION)
        {
            options->ce.tls_crypt_file = p[1];
            options->ce.tls_crypt_file_inline = is_inline;
        }
    }
    else if (streq(p[0], "tls-crypt-v2") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION|OPT_P_INLINE);
        if (permission_mask & OPT_P_GENERAL)
        {
            options->tls_crypt_v2_file = p[1];
            options->tls_crypt_v2_file_inline = is_inline;
        }
        else if (permission_mask & OPT_P_CONNECTION)
        {
            options->ce.tls_crypt_v2_file = p[1];
            options->ce.tls_crypt_v2_file_inline = is_inline;
        }

        if (p[2] && streq(p[2], "force-cookie"))
        {
            options->ce.tls_crypt_v2_force_cookie = true;
        }
        else if (p[2] && streq(p[2], "allow-noncookie"))
        {
            options->ce.tls_crypt_v2_force_cookie = false;
        }
        else if (p[2])
        {
            msg(msglevel, "Unsupported tls-crypt-v2 argument: %s", p[2]);
        }
    }
    else if (streq(p[0], "tls-crypt-v2-verify") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->tls_crypt_v2_verify_script = p[1];
    }
    else if (streq(p[0], "x509-track") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        x509_track_add(&options->x509_track, p[1], msglevel, &options->gc);
    }
#ifdef ENABLE_X509ALTUSERNAME
    else if (streq(p[0], "x509-username-field") && p[1])
    {
        /* This option used to automatically upcase the fieldnames passed as the
         * option arguments, e.g., "ou" became "OU". Now, this "helpfulness" is
         * fine-tuned by only upcasing Subject field attribute names which consist
         * of all lower-case characters. Mixed-case attributes such as
         * "emailAddress" are left as-is. An option parameter having the "ext:"
         * prefix for matching X.509v3 extended fields will also remain unchanged.
         */
        VERIFY_PERMISSION(OPT_P_GENERAL);
        for (size_t j = 1; j < MAX_PARMS && p[j] != NULL; ++j)
        {
            char *s = p[j];

            if (strncmp("ext:", s, 4) != 0)
            {
                size_t i = 0;
                while (s[i] && !isupper(s[i]))
                {
                    i++;
                }
                if (strlen(s) == i)
                {
                    while ((*s = toupper(*s)) != '\0')
                    {
                        s++;
                    }
                    msg(M_WARN, "DEPRECATED FEATURE: automatically upcased the "
                        "--x509-username-field parameter to '%s'; please update your"
                        "configuration", p[j]);
                }
            }
            else if (!x509_username_field_ext_supported(s+4))
            {
                msg(msglevel, "Unsupported x509-username-field extension: %s", s);
            }
            options->x509_username_field[j-1] = p[j];
        }
    }
#endif /* ENABLE_X509ALTUSERNAME */
#ifdef ENABLE_PKCS11
    else if (streq(p[0], "show-pkcs11-ids") && !p[3])
    {
        char *provider =  p[1];
        bool cert_private = (p[2] == NULL ? false : ( atoi(p[2]) != 0 ));

#ifdef DEFAULT_PKCS11_MODULE
        if (!provider)
        {
            provider = DEFAULT_PKCS11_MODULE;
        }
        else if (!p[2])
        {
            char *endp = NULL;
            int i = strtol(provider, &endp, 10);

            if (*endp == 0)
            {
                /* There was one argument, and it was purely numeric.
                 * Interpret it as the cert_private argument */
                provider = DEFAULT_PKCS11_MODULE;
                cert_private = i;
            }
        }
#else  /* ifdef DEFAULT_PKCS11_MODULE */
        if (!provider)
        {
            msg(msglevel, "--show-pkcs11-ids requires a provider parameter");
            goto err;
        }
#endif /* ifdef DEFAULT_PKCS11_MODULE */
        VERIFY_PERMISSION(OPT_P_GENERAL);

        set_debug_level(options->verbosity, SDL_CONSTRAIN);
        show_pkcs11_ids(provider, cert_private);
        openvpn_exit(OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }
    else if (streq(p[0], "pkcs11-providers") && p[1])
    {
        int j;

        VERIFY_PERMISSION(OPT_P_GENERAL);

        for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j)
        {
            options->pkcs11_providers[j-1] = p[j];
        }
    }
    else if (streq(p[0], "pkcs11-protected-authentication"))
    {
        int j;

        VERIFY_PERMISSION(OPT_P_GENERAL);

        for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j)
        {
            options->pkcs11_protected_authentication[j-1] = atoi(p[j]) != 0 ? 1 : 0;
        }
    }
    else if (streq(p[0], "pkcs11-private-mode") && p[1])
    {
        int j;

        VERIFY_PERMISSION(OPT_P_GENERAL);

        for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j)
        {
            sscanf(p[j], "%x", &(options->pkcs11_private_mode[j-1]));
        }
    }
    else if (streq(p[0], "pkcs11-cert-private"))
    {
        int j;

        VERIFY_PERMISSION(OPT_P_GENERAL);

        for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j)
        {
            options->pkcs11_cert_private[j-1] = atoi(p[j]) != 0 ? 1 : 0;
        }
    }
    else if (streq(p[0], "pkcs11-pin-cache") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->pkcs11_pin_cache_period = atoi(p[1]);
    }
    else if (streq(p[0], "pkcs11-id") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->pkcs11_id = p[1];
    }
    else if (streq(p[0], "pkcs11-id-management") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->pkcs11_id_management = true;
    }
#endif /* ifdef ENABLE_PKCS11 */
    else if (streq(p[0], "rmtun") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->persist_config = true;
        options->persist_mode = 0;
    }
    else if (streq(p[0], "mktun") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->persist_config = true;
        options->persist_mode = 1;
    }
    else if (streq(p[0], "peer-id") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_PEER_ID);
        options->use_peer_id = true;
        options->peer_id = atoi(p[1]);
    }
#ifdef HAVE_EXPORT_KEYING_MATERIAL
    else if (streq(p[0], "keying-material-exporter") && p[1] && p[2])
    {
        int ekm_length = positive_atoi(p[2]);

        VERIFY_PERMISSION(OPT_P_GENERAL);

        if (strncmp(p[1], "EXPORTER", 8))
        {
            msg(msglevel, "Keying material exporter label must begin with "
                "\"EXPORTER\"");
            goto err;
        }
        if (streq(p[1], EXPORT_KEY_DATA_LABEL))
        {
            msg(msglevel, "Keying material exporter label must not be '"
                EXPORT_KEY_DATA_LABEL "'.");
        }
        if (ekm_length < 16 || ekm_length > 4095)
        {
            msg(msglevel, "Invalid keying material exporter length");
            goto err;
        }

        options->keying_material_exporter_label = p[1];
        options->keying_material_exporter_length = ekm_length;
    }
#endif /* HAVE_EXPORT_KEYING_MATERIAL */
    else if (streq(p[0], "allow-recursive-routing") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->allow_recursive_routing = true;
    }
    else if (streq(p[0], "vlan-tagging") && !p[1])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->vlan_tagging = true;
    }
    else if (streq(p[0], "vlan-accept") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        if (streq(p[1], "tagged"))
        {
            options->vlan_accept = VLAN_ONLY_TAGGED;
        }
        else if (streq(p[1], "untagged"))
        {
            options->vlan_accept = VLAN_ONLY_UNTAGGED_OR_PRIORITY;
        }
        else if (streq(p[1], "all"))
        {
            options->vlan_accept = VLAN_ALL;
        }
        else
        {
            msg(msglevel, "--vlan-accept must be 'tagged', 'untagged' or 'all'");
            goto err;
        }
    }
    else if (streq(p[0], "vlan-pvid") && p[1] && !p[2])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_INSTANCE);
        options->vlan_pvid = positive_atoi(p[1]);
        if (options->vlan_pvid < OPENVPN_8021Q_MIN_VID
            || options->vlan_pvid > OPENVPN_8021Q_MAX_VID)
        {
            msg(msglevel,
                "the parameter of --vlan-pvid parameters must be >= %u and <= %u",
                OPENVPN_8021Q_MIN_VID, OPENVPN_8021Q_MAX_VID);
            goto err;
        }
    }
    else
    {
        int i;
        int msglevel_unknown = msglevel_fc;
        /* Check if an option is in --ignore-unknown-option and
         * set warning level to non fatal */
        for (i = 0; options->ignore_unknown_option && options->ignore_unknown_option[i]; i++)
        {
            if (streq(p[0], options->ignore_unknown_option[i]))
            {
                msglevel_unknown = M_WARN;
                break;
            }
        }
        if (file)
        {
            msg(msglevel_unknown, "Unrecognized option or missing or extra parameter(s) in %s:%d: %s (%s)", file, line, p[0], PACKAGE_VERSION);
        }
        else
        {
            msg(msglevel_unknown, "Unrecognized option or missing or extra parameter(s): --%s (%s)", p[0], PACKAGE_VERSION);
        }
    }
err:
    gc_free(&gc);
}
