/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2013 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2008-2013 David Sommerseth <dazo@users.sourceforge.net>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * 2004-01-28: Added Socks5 proxy support
 *   (Christof Meerwald, http://cmeerw.org)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif
#ifdef HAVE_CONFIG_VERSION_H
#include "config-version.h"
#endif

#include "syshead.h"

#include "buffer.h"
#include "error.h"
#include "common.h"
#include "shaper.h"
#include "crypto.h"
#include "ssl.h"
#include "options.h"
#include "misc.h"
#include "socket.h"
#include "packet_id.h"
#include "pkcs11.h"
#include "win32.h"
#include "push.h"
#include "pool.h"
#include "helper.h"
#include "manage.h"
#include "forward.h"
#include <ctype.h>

#include "memdbg.h"

const char title_string[] =
  PACKAGE_STRING
  " " TARGET_ALIAS
#ifdef ENABLE_CRYPTO
#ifdef ENABLE_SSL
#if defined(ENABLE_CRYPTO_POLARSSL)
  " [SSL (PolarSSL)]"
#elif defined(ENABLE_CRYPTO_OPENSSL)
  " [SSL (OpenSSL)]"
#else
  " [SSL]"
#endif /* defined(ENABLE_CRYPTO_POLARSSL) */
#else /* ! ENABLE_SSL */
#if defined(ENABLE_CRYPTO_POLARSSL)
  " [CRYPTO (PolarSSL)]"
#elif defined(ENABLE_CRYPTO_OPENSSL)
  " [CRYPTO (OpenSSL)]"
#else
  " [CRYPTO]"
#endif /* defined(ENABLE_CRYPTO_POLARSSL) */
#endif /* ENABLE_SSL */
#endif /* ENABLE_CRYPTO */
#ifdef ENABLE_LZO
#ifdef ENABLE_LZO_STUB
  " [LZO (STUB)]"
#else
  " [LZO]"
#endif
#endif
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
  " [MH]"
#endif
  " [IPv6]"
  " built on " __DATE__
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
  "                  p = udp (default), tcp-server, or tcp-client\n"
  "--proto-force p : only consider protocol p in list of connection profiles.\n"
  "                  p = udp6, tcp6-server, or tcp6-client (ipv6)\n"
  "--connect-retry n : For --proto tcp-client, number of seconds to wait\n"
  "                    between connection retries (default=%d).\n"
  "--connect-timeout n : For --proto tcp-client, connection timeout (in seconds).\n"
  "--connect-retry-max n : Maximum connection attempt retries, default infinite.\n"
#ifdef ENABLE_HTTP_PROXY
  "--http-proxy s p [up] [auth] : Connect to remote host\n"
  "                  through an HTTP proxy at address s and port p.\n"
  "                  If proxy authentication is required,\n"
  "                  up is a file containing username/password on 2 lines, or\n"
  "                  'stdin' to prompt from console.  Add auth='ntlm' if\n"
  "                  the proxy requires NTLM authentication.\n"
  "--http-proxy s p 'auto[-nct]' : Like the above directive, but automatically\n"
  "                  determine auth method and query for username/password\n"
  "                  if needed.  auto-nct disables weak proxy auth methods.\n"
  "--http-proxy-retry     : Retry indefinitely on HTTP proxy errors.\n"
  "--http-proxy-timeout n : Proxy timeout in seconds, default=5.\n"
  "--http-proxy-option type [parm] : Set extended HTTP proxy options.\n"
  "                                  Repeat to set multiple options.\n"
  "                  VERSION version (default=1.0)\n"
  "                  AGENT user-agent\n"
#endif
#ifdef ENABLE_SOCKS
  "--socks-proxy s [p] [up] : Connect to remote host through a Socks5 proxy at\n"
  "                  address s and port p (default port = 1080).\n"
  "                  If proxy authentication is required,\n"
  "                  up is a file containing username/password on 2 lines, or\n"
  "                  'stdin' to prompt for console.\n"
  "--socks-proxy-retry : Retry indefinitely on Socks proxy errors.\n"
#endif
  "--resolv-retry n: If hostname resolve fails for --remote, retry\n"
  "                  resolve for n seconds before failing (disabled by default).\n"
  "                  Set n=\"infinite\" to retry indefinitely.\n"
  "--float         : Allow remote to change its IP address/port, such as through\n"
  "                  DHCP (this is the default if --remote is not used).\n"
  "--ipchange cmd  : Run command cmd on remote ip address initial\n"
  "                  setting or change -- execute as: cmd ip-address port#\n"
  "--port port     : TCP/UDP port # for both local and remote.\n"
  "--lport port    : TCP/UDP port # for local (default=%d). Implies --bind.\n"
  "--rport port    : TCP/UDP port # for remote (default=%d).\n"
  "--bind          : Bind to local address and port. (This is the default unless\n"
  "                  --proto tcp-client"
#ifdef ENABLE_HTTP_PROXY
                   " or --http-proxy"
#endif
#ifdef ENABLE_SOCKS
                   " or --socks-proxy"
#endif
                   " is used).\n"
  "--nobind        : Do not bind to local address and port.\n"
  "--dev tunX|tapX : tun/tap device (X can be omitted for dynamic device.\n"
  "--dev-type dt   : Which device type are we using? (dt = tun or tap) Use\n"
  "                  this option only if the tun/tap device used with --dev\n"
  "                  does not begin with \"tun\" or \"tap\".\n"
  "--dev-node node : Explicitly set the device node rather than using\n"
  "                  /dev/net/tun, /dev/tun, /dev/tap, etc.\n"
  "--lladdr hw     : Set the link layer address of the tap device.\n"
  "--topology t    : Set --dev tun topology: 'net30', 'p2p', or 'subnet'.\n"
  "--tun-ipv6      : Build tun link capable of forwarding IPv6 traffic.\n"
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
  "                  Specify default by leaving blank or setting to \"nil\".\n"
  "--route-ipv6 network/bits [gateway] [metric] :\n"
  "                  Add IPv6 route to routing table after connection\n"
  "                  is established.  Multiple routes can be specified.\n"
  "                  gateway default: taken from --route-ipv6-gateway or --ifconfig\n"
  "--max-routes n :  Specify the maximum number of routes that may be defined\n"
  "                  or pulled from a server.\n"
  "--route-gateway gw|'dhcp' : Specify a default gateway for use with --route.\n"
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
  "                  by server EXCEPT for routes and dhcp options.\n"
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
#ifdef ENABLE_CLIENT_NAT
  "--client-nat snat|dnat network netmask alias : on client add 1-to-1 NAT rule.\n"
#endif
#ifdef ENABLE_PUSH_PEER_INFO
  "--push-peer-info : (client only) push client info to server.\n"
#endif
  "--setenv name value : Set a custom environmental variable to pass to script.\n"
  "--setenv FORWARD_COMPATIBLE 1 : Relax config file syntax checking to allow\n"
  "                  directives for future OpenVPN versions to be ignored.\n"
  "--ignore-unkown-option opt1 opt2 ...: Relax config file syntax. Allow\n"
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
  "--ping-exit n   : Exit if n seconds pass without reception of remote ping.\n"
  "--ping-restart n: Restart if n seconds pass without reception of remote ping.\n"
  "--ping-timer-rem: Run the --ping-exit/--ping-restart timer only if we have a\n"
  "                  remote address.\n"
  "--ping n        : Ping remote once every n seconds over TCP/UDP port.\n"
#if ENABLE_IP_PKTINFO
  "--multihome     : Configure a multi-homed UDP server.\n"
#endif
  "--fast-io       : (experimental) Optimize TUN/TAP/UDP writes.\n"
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
#ifdef ENABLE_OCC
  "--mtu-test      : Empirically measure and report MTU.\n"
#endif
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
  "--inetd [name] ['wait'|'nowait'] : Run as an inetd or xinetd server.\n"
  "                  See --daemon above for a description of the 'name' parm.\n"
  "--log file      : Output log to file which is created/truncated on open.\n"
  "--log-append file : Append log to file, or create file if nonexistent.\n"
  "--suppress-timestamps : Don't log timestamps to stdout/stderr.\n"
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
  "--status file n : Write operational status to file every n seconds.\n"
  "--status-version [n] : Choose the status file format version number.\n"
  "                  Currently, n can be 1, 2, or 3 (default=1).\n"
#ifdef ENABLE_OCC
  "--disable-occ   : Disable options consistency check between peers.\n"
#endif
#ifdef ENABLE_DEBUG
  "--gremlin mask  : Special stress testing mode (for debugging only).\n"
#endif
#ifdef ENABLE_LZO
  "--comp-lzo      : Use fast LZO compression -- may add up to 1 byte per\n"
  "                  packet for uncompressible data.\n"
  "--comp-noadapt  : Don't use adaptive compression when --comp-lzo\n"
  "                  is specified.\n"
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
#ifdef MANAGEMENT_DEF_AUTH
  "--management-client-auth : gives management interface client the responsibility\n"
  "                           to authenticate clients after their client certificate\n"
  "			      has been verified.\n"
#endif
#ifdef MANAGEMENT_PF
  "--management-client-pf : management interface clients must specify a packet\n"
  "                         filter file for each connecting client.\n"
#endif
#endif
#ifdef ENABLE_PLUGIN
  "--plugin m [str]: Load plug-in module m passing str as an argument\n"
  "                  to its initialization function.\n"
#endif
#if P2MP
#if P2MP_SERVER
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
  "--ifconfig-pool start-IP end-IP [netmask] : Set aside a pool of subnets\n"
  "                  to be dynamically allocated to connecting clients.\n"
  "--ifconfig-pool-linear : Use individual addresses rather than /30 subnets\n"
  "                  in tun mode.  Not compatible with Windows clients.\n"
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
  "--client-cert-not-required : Don't require client certificate, client\n"
  "                  will authenticate using username/password.\n"
  "--username-as-common-name  : For auth-user-pass authentication, use\n"
  "                  the authenticated username as the common name,\n"
  "                  rather than the common name from the client cert.\n"
  "--auth-user-pass-verify cmd method: Query client for username/password and\n"
  "                  run command cmd to verify.  If method='via-env', pass\n"
  "                  user/pass via environment, if method='via-file', pass\n"
  "                  user/pass via temporary file.\n"
  "--opt-verify    : Clients that connect with options that are incompatible\n"
  "                  with those of the server will be disconnected.\n"
  "--auth-user-pass-optional : Allow connections by clients that don't\n"
  "                  specify a username/password.\n"
  "--no-name-remapping : Allow Common Name and X509 Subject to include\n"
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
  "--max-clients n : Allow a maximum of n simultaneously connected clients.\n"
  "--max-routes-per-client n : Allow a maximum of n internal routes per client.\n"
  "--stale-routes-check n [t] : Remove routes with a last activity timestamp\n"
  "                             older than n seconds. Run this check every t\n"
  "                             seconds (defaults to n).\n"
#if PORT_SHARE
  "--port-share host port [dir] : When run in TCP mode, proxy incoming HTTPS\n"
  "                  sessions to a web server at host:port.  dir specifies an\n"
  "                  optional directory to write origin IP:port data.\n"
#endif
#endif
  "\n"
  "Client options (when connecting to a multi-client server):\n"
  "--client         : Helper option to easily configure client mode.\n"
  "--auth-user-pass [up] : Authenticate with server using username/password.\n"
  "                  up is a file containing username/password on 2 lines,\n"
  "                  or omit to prompt from console.\n"
  "--pull           : Accept certain config file options from the peer as if they\n"
  "                  were part of the local config file.  Must be specified\n"
  "                  when connecting to a '--mode server' remote host.\n"
  "--auth-retry t  : How to handle auth failures.  Set t to\n"
  "                  none (default), interact, or nointeract.\n"
  "--static-challenge t e : Enable static challenge/response protocol using\n"
  "                  challenge text t, with e indicating echo flag (0|1)\n"
  "--server-poll-timeout n : when polling possible remote servers to connect to\n"
  "                  in a round-robin fashion, spend no more than n seconds\n"
  "                  waiting for a response before trying the next server.\n"
#endif
#ifdef ENABLE_OCC
  "--explicit-exit-notify [n] : On exit/restart, send exit signal to\n"
  "                  server/remote. n = # of retries, default=1.\n"
#endif
#ifdef ENABLE_CRYPTO
  "\n"
  "Data Channel Encryption Options (must be compatible between peers):\n"
  "(These options are meaningful for both Static Key & TLS-mode)\n"
  "--secret f [d]  : Enable Static Key encryption mode (non-TLS).\n"
  "                  Use shared secret file f, generate with --genkey.\n"
  "                  The optional d parameter controls key directionality.\n"
  "                  If d is specified, use separate keys for each\n"
  "                  direction, set d=0 on one side of the connection,\n"
  "                  and d=1 on the other side.\n"
  "--auth alg      : Authenticate packets with HMAC using message\n"
  "                  digest algorithm alg (default=%s).\n"
  "                  (usually adds 16 or 20 bytes per packet)\n"
  "                  Set alg=none to disable authentication.\n"
  "--cipher alg    : Encrypt packets with cipher algorithm alg\n"
  "                  (default=%s).\n"
  "                  Set alg=none to disable encryption.\n"
  "--prng alg [nsl] : For PRNG, use digest algorithm alg, and\n"
  "                   nonce_secret_len=nsl.  Set alg=none to disable PRNG.\n"
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
  "--keysize n     : Size of cipher key in bits (optional).\n"
  "                  If unspecified, defaults to cipher-specific default.\n"
#endif
#ifndef ENABLE_CRYPTO_POLARSSL
  "--engine [name] : Enable OpenSSL hardware crypto engine functionality.\n"
#endif
  "--no-replay     : Disable replay protection.\n"
  "--mute-replay-warnings : Silence the output of replay warnings to log file.\n"
  "--replay-window n [t]  : Use a replay protection sliding window of size n\n"
  "                         and a time window of t seconds.\n"
  "                         Default n=%d t=%d\n"
  "--no-iv         : Disable cipher IV -- only allowed with CBC mode ciphers.\n"
  "--replay-persist file : Persist replay-protection state across sessions\n"
  "                  using file.\n"
  "--test-crypto   : Run a self-test of crypto features enabled.\n"
  "                  For debugging only.\n"
#ifdef ENABLE_PREDICTION_RESISTANCE
  "--use-prediction-resistance: Enable prediction resistance on the random\n"
  "                             number generator.\n"
#endif
#ifdef ENABLE_SSL
  "\n"
  "TLS Key Negotiation Options:\n"
  "(These options are meaningful only for TLS-mode)\n"
  "--tls-server    : Enable TLS and assume server role during TLS handshake.\n"
  "--tls-client    : Enable TLS and assume client role during TLS handshake.\n"
  "--key-method m  : Data channel key exchange method.  m should be a method\n"
  "                  number, such as 1 (default), 2, etc.\n"
  "--ca file       : Certificate authority file in .pem format containing\n"
  "                  root certificate.\n"
#ifndef ENABLE_CRYPTO_POLARSSL
  "--capath dir    : A directory of trusted certificates (CAs"
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
  " and CRLs).\n"
#else /* OPENSSL_VERSION_NUMBER >= 0x00907000L */
  ").\n"
  "                  WARNING: no support of CRL available with this version.\n"
#endif /* OPENSSL_VERSION_NUMBER >= 0x00907000L */
#endif /* ENABLE_CRYPTO_POLARSSL */
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
#ifndef ENABLE_CRYPTO_POLARSSL
  "--pkcs12 file   : PKCS#12 file containing local private key, local certificate\n"
  "                  and optionally the root CA certificate.\n"
#endif
#ifdef ENABLE_X509ALTUSERNAME
  "--x509-username-field : Field in x509 certificate containing the username.\n"
  "                        Default is CN in the Subject field.\n"
#endif
  "--verify-hash   : Specify SHA1 fingerprint for level-1 cert.\n"
#ifdef WIN32
  "--cryptoapicert select-string : Load the certificate and private key from the\n"
  "                  Windows Certificate System Store.\n"
#endif
  "--tls-cipher l  : A list l of allowable TLS ciphers separated by : (optional).\n"
  "                : Use --show-tls to see a list of supported TLS ciphers.\n"
  "--tls-timeout n : Packet retransmit timeout on TLS control channel\n"
  "                  if no ACK from remote within n seconds (default=%d).\n"
  "--reneg-bytes n : Renegotiate data chan. key after n bytes sent and recvd.\n"
  "--reneg-pkts n  : Renegotiate data chan. key after n packets sent and recvd.\n"
  "--reneg-sec n   : Renegotiate data chan. key after n seconds (default=%d).\n"
  "--hand-window n : Data channel key exchange must finalize within n seconds\n"
  "                  of handshake initiation by any peer (default=%d).\n"
  "--tran-window n : Transition window -- old key can live this many seconds\n"
  "                  after new key renegotiation begins (default=%d).\n"
  "--single-session: Allow only one session (reset state on restart).\n"
  "--tls-exit      : Exit on TLS negotiation failure.\n"
  "--tls-auth f [d]: Add an additional layer of authentication on top of the TLS\n"
  "                  control channel to protect against DoS attacks.\n"
  "                  f (required) is a shared-secret passphrase file.\n"
  "                  The optional d parameter controls key directionality,\n"
  "                  see --secret option for more info.\n"
  "--askpass [file]: Get PEM password from controlling tty before we daemonize.\n"
  "--auth-nocache  : Don't cache --askpass or --auth-user-pass passwords.\n"
  "--crl-verify crl ['dir']: Check peer certificate against a CRL.\n"
  "--tls-verify cmd: Run command cmd to verify the X509 name of a\n"
  "                  pending TLS connection that has otherwise passed all other\n"
  "                  tests of certification.  cmd should return 0 to allow\n"
  "                  TLS handshake to proceed, or 1 to fail.  (cmd is\n"
  "                  executed as 'cmd certificate_depth subject')\n"
  "--tls-export-cert [directory] : Get peer cert in PEM format and store it \n"
  "                  in an openvpn temporary file in [directory]. Peer cert is \n"
  "                  stored before tls-verify script execution and deleted after.\n"
  "--verify-x509-name name: Accept connections only from a host with X509 subject\n"
  "                  DN name. The remote host must also pass all other tests\n"
  "                  of verification.\n"
  "--ns-cert-type t: Require that peer certificate was signed with an explicit\n"
  "                  nsCertType designation t = 'client' | 'server'.\n"
#ifdef ENABLE_X509_TRACK
  "--x509-track x  : Save peer X509 attribute x in environment for use by\n"
  "                  plugins and management interface.\n"
#endif
#if OPENSSL_VERSION_NUMBER >= 0x00907000L || ENABLE_CRYPTO_POLARSSL
  "--remote-cert-ku v ... : Require that the peer certificate was signed with\n"
  "                  explicit key usage, you can specify more than one value.\n"
  "                  value should be given in hex format.\n"
  "--remote-cert-eku oid : Require that the peer certificate was signed with\n"
  "                  explicit extended key usage. Extended key usage can be encoded\n"
  "                  as an object identifier or OpenSSL string representation.\n"
  "--remote-cert-tls t: Require that peer certificate was signed with explicit\n"
  "                  key usage and extended key usage based on RFC3280 TLS rules.\n"
  "                  t = 'client' | 'server'.\n"
#endif				/* OPENSSL_VERSION_NUMBER || ENABLE_CRYPTO_POLARSSL */
#endif				/* ENABLE_SSL */
#ifdef ENABLE_PKCS11
  "\n"
  "PKCS#11 Options:\n"
  "--pkcs11-providers provider ... : PKCS#11 provider to load.\n"
  "--pkcs11-protected-authentication [0|1] ... : Use PKCS#11 protected authentication\n"
  "                              path. Set for each provider.\n"
  "--pkcs11-private-mode hex ...   : PKCS#11 private key mode mask.\n"
  "                              0       : Try  to determind automatically (default).\n"
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
#endif			/* ENABLE_PKCS11 */
 "\n"
  "SSL Library information:\n"
  "--show-ciphers  : Show cipher algorithms to use with --cipher option.\n"
  "--show-digests  : Show message digest algorithms to use with --auth option.\n"
  "--show-engines  : Show hardware crypto accelerator engines (if available).\n"
#ifdef ENABLE_SSL
  "--show-tls      : Show all TLS ciphers (TLS used only as a control channel).\n"
#endif
#ifdef WIN32
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
  "                    DNS addr    : Set domain name server address(es)\n"
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
  "--dhcp-release     : Ask Windows to release the TAP adapter lease on shutdown.\n"
  "--register-dns  : Run net stop dnscache, net start dnscache, ipconfig /flushdns\n"
  "                  and ipconfig /registerdns on connection initiation.\n"
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
  "Windows Standalone Options:\n"
  "\n"
  "--show-adapters : Show all TAP-Windows adapters.\n"
  "--show-net      : Show " PACKAGE_NAME "'s view of routing table and net adapter list.\n"
  "--show-valid-subnets : Show valid subnets for --dev tun emulation.\n"
  "--allow-nonadmin [TAP-adapter] : Allow " PACKAGE_NAME " running without admin privileges\n"
  "                                 to access TAP adapter.\n"
#endif
  "\n"
  "Generate a random key (only for non-TLS static key encryption mode):\n"
  "--genkey        : Generate a random key to be used as a shared secret,\n"
  "                  for use with the --secret option.\n"
  "--secret file   : Write key to file.\n"
#endif				/* ENABLE_CRYPTO */
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
#endif				/* ENABLE_PKCS11 */
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
init_options (struct options *o, const bool init_gc)
{
  CLEAR (*o);
  if (init_gc)
    {
      gc_init (&o->gc);
      o->gc_owned = true;
    }
  o->mode = MODE_POINT_TO_POINT;
  o->topology = TOP_NET30;
  o->ce.proto = PROTO_UDPv4;
  o->ce.connect_retry_seconds = 5;
  o->ce.connect_timeout = 10;
  o->ce.connect_retry_max = 0;
  o->ce.local_port = o->ce.remote_port = OPENVPN_PORT;
  o->verbosity = 1;
  o->status_file_update_freq = 60;
  o->status_file_version = 1;
  o->ce.bind_local = true;
  o->ce.tun_mtu = TUN_MTU_DEFAULT;
  o->ce.link_mtu = LINK_MTU_DEFAULT;
  o->ce.mtu_discover_type = -1;
  o->ce.mssfix = MSSFIX_DEFAULT;
  o->route_delay_window = 30;
  o->max_routes = MAX_ROUTES_DEFAULT;
  o->resolve_retry_seconds = RESOLV_RETRY_INFINITE;
  o->proto_force = -1;
#ifdef ENABLE_OCC
  o->occ = true;
#endif
#ifdef ENABLE_MANAGEMENT
  o->management_log_history_cache = 250;
  o->management_echo_buffer_size = 100;
  o->management_state_buffer_size = 100;
#endif
#ifdef ENABLE_FEATURE_TUN_PERSIST
  o->persist_mode = 1;
#endif
#ifndef WIN32
  o->rcvbuf = 65536;
  o->sndbuf = 65536;
#endif
#ifdef TARGET_LINUX
  o->tuntap_options.txqueuelen = 100;
#endif
#ifdef WIN32
#if 0
  o->tuntap_options.ip_win32_type = IPW32_SET_ADAPTIVE;
#else
  o->tuntap_options.ip_win32_type = IPW32_SET_DHCP_MASQ;
#endif
  o->tuntap_options.dhcp_lease_time = 31536000; /* one year */
  o->tuntap_options.dhcp_masq_offset = 0;       /* use network address as internal DHCP server address */
  o->route_method = ROUTE_METHOD_ADAPTIVE;
#endif
#if P2MP_SERVER
  o->real_hash_size = 256;
  o->virtual_hash_size = 256;
  o->n_bcast_buf = 256;
  o->tcp_queue_limit = 64;
  o->max_clients = 1024;
  o->max_routes_per_client = 256;
  o->stale_routes_check_interval = 0;
  o->ifconfig_pool_persist_refresh_freq = 600;
#endif
#if P2MP
  o->scheduled_exit_interval = 5;
  o->server_poll_timeout = 0;
#endif
#ifdef ENABLE_CRYPTO
  o->ciphername = "BF-CBC";
  o->ciphername_defined = true;
  o->authname = "SHA1";
  o->authname_defined = true;
  o->prng_hash = "SHA1";
  o->prng_nonce_secret_len = 16;
  o->replay = true;
  o->replay_window = DEFAULT_SEQ_BACKTRACK;
  o->replay_time = DEFAULT_TIME_BACKTRACK;
  o->use_iv = true;
  o->key_direction = KEY_DIRECTION_BIDIRECTIONAL;
#ifdef ENABLE_PREDICTION_RESISTANCE
  o->use_prediction_resistance = false;
#endif
#ifdef ENABLE_SSL
  o->key_method = 2;
  o->tls_timeout = 2;
  o->renegotiate_seconds = 3600;
  o->handshake_window = 60;
  o->transition_window = 3600;
#ifdef ENABLE_X509ALTUSERNAME
  o->x509_username_field = X509_USERNAME_FIELD_DEFAULT;
#endif
#endif /* ENABLE_SSL */
#endif /* ENABLE_CRYPTO */
#ifdef ENABLE_PKCS11
  o->pkcs11_pin_cache_period = -1;
#endif			/* ENABLE_PKCS11 */

/* tmp is only used in P2MP server context */
#if P2MP_SERVER
  /* Set default --tmp-dir */
#ifdef WIN32
  /* On Windows, find temp dir via enviroment variables */
  o->tmp_dir = win_get_tempdir();
#else
  /* Non-windows platforms use $TMPDIR, and if not set, default to '/tmp' */
  o->tmp_dir = getenv("TMPDIR");
  if( !o->tmp_dir ) {
          o->tmp_dir = "/tmp";
  }
#endif /* WIN32 */
#endif /* P2MP_SERVER */
}

void
uninit_options (struct options *o)
{
  if (o->gc_owned)
    {
      gc_free (&o->gc);
    }
}

#ifndef ENABLE_SMALL

#define SHOW_PARM(name, value, format) msg(D_SHOW_PARMS, "  " #name " = " format, (value))
#define SHOW_STR(var)       SHOW_PARM(var, (o->var ? o->var : "[UNDEF]"), "'%s'")
#define SHOW_INT(var)       SHOW_PARM(var, o->var, "%d")
#define SHOW_UINT(var)      SHOW_PARM(var, o->var, "%u")
#define SHOW_UNSIGNED(var)  SHOW_PARM(var, o->var, "0x%08x")
#define SHOW_BOOL(var)      SHOW_PARM(var, (o->var ? "ENABLED" : "DISABLED"), "%s");

#endif

void
setenv_connection_entry (struct env_set *es,
			 const struct connection_entry *e,
			 const int i)
{
  setenv_str_i (es, "proto", proto2ascii (e->proto, false), i);
  setenv_str_i (es, "local", e->local, i);
  setenv_int_i (es, "local_port", e->local_port, i);
  setenv_str_i (es, "remote", e->remote, i);
  setenv_int_i (es, "remote_port", e->remote_port, i);

#ifdef ENABLE_HTTP_PROXY
  if (e->http_proxy_options)
    {
      setenv_str_i (es, "http_proxy_server", e->http_proxy_options->server, i);
      setenv_int_i (es, "http_proxy_port", e->http_proxy_options->port, i);
    }
#endif
#ifdef ENABLE_SOCKS
  if (e->socks_proxy_server)
    {
      setenv_str_i (es, "socks_proxy_server", e->socks_proxy_server, i);
      setenv_int_i (es, "socks_proxy_port", e->socks_proxy_port, i);
    }
#endif
}

void
setenv_settings (struct env_set *es, const struct options *o)
{
  setenv_str (es, "config", o->config);
  setenv_int (es, "verb", o->verbosity);
  setenv_int (es, "daemon", o->daemon);
  setenv_int (es, "daemon_log_redirect", o->log);
  setenv_unsigned (es, "daemon_start_time", time(NULL));
  setenv_int (es, "daemon_pid", platform_getpid());

  if (o->connection_list)
    {
      int i;
      for (i = 0; i < o->connection_list->len; ++i)
	setenv_connection_entry (es, o->connection_list->array[i], i+1);
    }
  else
    setenv_connection_entry (es, &o->ce, 1);
}

static in_addr_t
get_ip_addr (const char *ip_string, int msglevel, bool *error)
{
  unsigned int flags = GETADDR_HOST_ORDER;
  bool succeeded = false;
  in_addr_t ret;

  if (msglevel & M_FATAL)
    flags |= GETADDR_FATAL;

  ret = getaddr (flags, ip_string, 0, &succeeded, NULL);
  if (!succeeded && error)
    *error = true;
  return ret;
}

/* helper: parse a text string containing an IPv6 address + netbits
 * in "standard format" (2001:dba::/32)
 * "/nn" is optional, default to /64 if missing
 *
 * return true if parsing succeeded, modify *network and *netbits
 * return address part without "/nn" in *printable_ipv6 (if != NULL)
 */
bool
get_ipv6_addr( const char * prefix_str, struct in6_addr *network,
	       unsigned int * netbits, char ** printable_ipv6, int msglevel )
{
    int rc;
    char * sep, * endp;
    int bits;
    struct in6_addr t_network;

    sep = strchr( prefix_str, '/' );
    if ( sep == NULL )
      {
 	bits = 64;
      }
    else
      {
	bits = strtol( sep+1, &endp, 10 );
	if ( *endp != '\0' || bits < 0 || bits > 128 )
	  {
	    msg (msglevel, "IPv6 prefix '%s': invalid '/bits' spec", prefix_str);
	    return false;
	  }
      }

    /* temporary replace '/' in caller-provided string with '\0', otherwise
     * inet_pton() will refuse prefix string
     * (alternative would be to strncpy() the prefix to temporary buffer)
     */

    if ( sep != NULL ) *sep = '\0';

    rc = inet_pton( AF_INET6, prefix_str, &t_network );

    if ( rc == 1 && printable_ipv6 != NULL )
      {
	*printable_ipv6 = string_alloc( prefix_str, NULL );
      }

    if ( sep != NULL ) *sep = '/';

    if ( rc != 1 )
      {
	msg (msglevel, "IPv6 prefix '%s': invalid IPv6 address", prefix_str);
	return false;
      }

    if ( netbits != NULL )
      {
	*netbits = bits;
      }
    if ( network != NULL )
      {
	*network = t_network;
      }
    return true;		/* parsing OK, values set */
}

static bool ipv6_addr_safe_hexplusbits( const char * ipv6_prefix_spec )
{
    struct in6_addr t_addr;
    unsigned int t_bits;

    return get_ipv6_addr( ipv6_prefix_spec, &t_addr, &t_bits, NULL, M_WARN );
}

static char *
string_substitute (const char *src, int from, int to, struct gc_arena *gc)
{
  char *ret = (char *) gc_malloc (strlen (src) + 1, true, gc);
  char *dest = ret;
  char c;

  do
    {
      c = *src++;
      if (c == from)
	c = to;
      *dest++ = c;
    }
  while (c);
  return ret;
}

#ifdef ENABLE_SSL
static uint8_t *
parse_hash_fingerprint(const char *str, int nbytes, int msglevel, struct gc_arena *gc)
{
  int i;
  const char *cp = str;
  uint8_t *ret = (uint8_t *) gc_malloc (nbytes, true, gc);
  char term = 1;
  int byte;
  char bs[3];

  for (i = 0; i < nbytes; ++i)
    {
      if (strlen(cp) < 2)
	msg (msglevel, "format error in hash fingerprint: %s", str);
      bs[0] = *cp++;
      bs[1] = *cp++;
      bs[2] = 0;
      byte = 0;
      if (sscanf(bs, "%x", &byte) != 1)
	msg (msglevel, "format error in hash fingerprint hex byte: %s", str);
      ret[i] = (uint8_t)byte;
      term = *cp++;
      if (term != ':' && term != 0)
	msg (msglevel, "format error in hash fingerprint delimiter: %s", str);
      if (term == 0)
	break;
    }
  if (term != 0 || i != nbytes-1)
    msg (msglevel, "hash fingerprint is different length than expected (%d bytes): %s", nbytes, str);
  return ret;
}
#endif

#ifdef WIN32

#ifndef ENABLE_SMALL

static void
show_dhcp_option_addrs (const char *name, const in_addr_t *array, int len)
{
  struct gc_arena gc = gc_new ();
  int i;
  for (i = 0; i < len; ++i)
    {
      msg (D_SHOW_PARMS, "  %s[%d] = %s",
	   name,
	   i,
	   print_in_addr_t (array[i], 0, &gc));
    }
  gc_free (&gc);
}

static void
show_tuntap_options (const struct tuntap_options *o)
{
  SHOW_BOOL (ip_win32_defined);
  SHOW_INT (ip_win32_type);
  SHOW_INT (dhcp_masq_offset);
  SHOW_INT (dhcp_lease_time);
  SHOW_INT (tap_sleep);
  SHOW_BOOL (dhcp_options);
  SHOW_BOOL (dhcp_renew);
  SHOW_BOOL (dhcp_pre_release);
  SHOW_BOOL (dhcp_release);
  SHOW_STR (domain);
  SHOW_STR (netbios_scope);
  SHOW_INT (netbios_node_type);
  SHOW_BOOL (disable_nbt);

  show_dhcp_option_addrs ("DNS", o->dns, o->dns_len);
  show_dhcp_option_addrs ("WINS", o->wins, o->wins_len);
  show_dhcp_option_addrs ("NTP", o->ntp, o->ntp_len);
  show_dhcp_option_addrs ("NBDD", o->nbdd, o->nbdd_len);
}

#endif

static void
dhcp_option_address_parse (const char *name, const char *parm, in_addr_t *array, int *len, int msglevel)
{
  if (*len >= N_DHCP_ADDR)
    {
      msg (msglevel, "--dhcp-option %s: maximum of %d %s servers can be specified",
	   name,
	   N_DHCP_ADDR,
	   name);
    }
  else
    {
      if (ip_addr_dotted_quad_safe (parm)) /* FQDN -- IP address only */
	{
	  bool error = false;
	  const in_addr_t addr = get_ip_addr (parm, msglevel, &error);
	  if (!error)
	    array[(*len)++] = addr;
	}
      else
	{
	  msg (msglevel, "dhcp-option parameter %s '%s' must be an IP address", name, parm);
	}
    }
}

#endif

#if P2MP

#ifndef ENABLE_SMALL

static void
show_p2mp_parms (const struct options *o)
{
  struct gc_arena gc = gc_new ();

#if P2MP_SERVER
  msg (D_SHOW_PARMS, "  server_network = %s", print_in_addr_t (o->server_network, 0, &gc));
  msg (D_SHOW_PARMS, "  server_netmask = %s", print_in_addr_t (o->server_netmask, 0, &gc));
  msg (D_SHOW_PARMS, "  server_network_ipv6 = %s", print_in6_addr (o->server_network_ipv6, 0, &gc) );
  SHOW_INT (server_netbits_ipv6);
  msg (D_SHOW_PARMS, "  server_bridge_ip = %s", print_in_addr_t (o->server_bridge_ip, 0, &gc));
  msg (D_SHOW_PARMS, "  server_bridge_netmask = %s", print_in_addr_t (o->server_bridge_netmask, 0, &gc));
  msg (D_SHOW_PARMS, "  server_bridge_pool_start = %s", print_in_addr_t (o->server_bridge_pool_start, 0, &gc));
  msg (D_SHOW_PARMS, "  server_bridge_pool_end = %s", print_in_addr_t (o->server_bridge_pool_end, 0, &gc));
  if (o->push_list.head)
    {
      const struct push_entry *e = o->push_list.head;
      while (e)
	{
	  if (e->enable)
	    msg (D_SHOW_PARMS, "  push_entry = '%s'", e->option);
	  e = e->next;
	}
    }
  SHOW_BOOL (ifconfig_pool_defined);
  msg (D_SHOW_PARMS, "  ifconfig_pool_start = %s", print_in_addr_t (o->ifconfig_pool_start, 0, &gc));
  msg (D_SHOW_PARMS, "  ifconfig_pool_end = %s", print_in_addr_t (o->ifconfig_pool_end, 0, &gc));
  msg (D_SHOW_PARMS, "  ifconfig_pool_netmask = %s", print_in_addr_t (o->ifconfig_pool_netmask, 0, &gc));
  SHOW_STR (ifconfig_pool_persist_filename);
  SHOW_INT (ifconfig_pool_persist_refresh_freq);
  SHOW_BOOL (ifconfig_ipv6_pool_defined);
  msg (D_SHOW_PARMS, "  ifconfig_ipv6_pool_base = %s", print_in6_addr (o->ifconfig_ipv6_pool_base, 0, &gc));
  SHOW_INT (ifconfig_ipv6_pool_netbits);
  SHOW_INT (n_bcast_buf);
  SHOW_INT (tcp_queue_limit);
  SHOW_INT (real_hash_size);
  SHOW_INT (virtual_hash_size);
  SHOW_STR (client_connect_script);
  SHOW_STR (learn_address_script);
  SHOW_STR (client_disconnect_script);
  SHOW_STR (client_config_dir);
  SHOW_BOOL (ccd_exclusive);
  SHOW_STR (tmp_dir);
  SHOW_BOOL (push_ifconfig_defined);
  msg (D_SHOW_PARMS, "  push_ifconfig_local = %s", print_in_addr_t (o->push_ifconfig_local, 0, &gc));
  msg (D_SHOW_PARMS, "  push_ifconfig_remote_netmask = %s", print_in_addr_t (o->push_ifconfig_remote_netmask, 0, &gc));
  SHOW_BOOL (push_ifconfig_ipv6_defined);
  msg (D_SHOW_PARMS, "  push_ifconfig_ipv6_local = %s/%d", print_in6_addr (o->push_ifconfig_ipv6_local, 0, &gc), o->push_ifconfig_ipv6_netbits );
  msg (D_SHOW_PARMS, "  push_ifconfig_ipv6_remote = %s", print_in6_addr (o->push_ifconfig_ipv6_remote, 0, &gc));
  SHOW_BOOL (enable_c2c);
  SHOW_BOOL (duplicate_cn);
  SHOW_INT (cf_max);
  SHOW_INT (cf_per);
  SHOW_INT (max_clients);
  SHOW_INT (max_routes_per_client);
  SHOW_STR (auth_user_pass_verify_script);
  SHOW_BOOL (auth_user_pass_verify_script_via_file);
#if PORT_SHARE
  SHOW_STR (port_share_host);
  SHOW_INT (port_share_port);
#endif
#endif /* P2MP_SERVER */

  SHOW_BOOL (client);
  SHOW_BOOL (pull);
  SHOW_STR (auth_user_pass_file);

  gc_free (&gc);
}

#endif /* ! ENABLE_SMALL */

#if P2MP_SERVER

static void
option_iroute (struct options *o,
	       const char *network_str,
	       const char *netmask_str,
	       int msglevel)
{
  struct iroute *ir;

  ALLOC_OBJ_GC (ir, struct iroute, &o->gc);
  ir->network = getaddr (GETADDR_HOST_ORDER, network_str, 0, NULL, NULL);
  ir->netbits = -1;

  if (netmask_str)
    {
      const in_addr_t netmask = getaddr (GETADDR_HOST_ORDER, netmask_str, 0, NULL, NULL);
      if (!netmask_to_netbits (ir->network, netmask, &ir->netbits))
	{
	  msg (msglevel, "in --iroute %s %s : Bad network/subnet specification",
	       network_str,
	       netmask_str);
	  return;
	}
    }

  ir->next = o->iroutes;
  o->iroutes = ir;
}

static void
option_iroute_ipv6 (struct options *o,
	       const char *prefix_str,
	       int msglevel)
{
  struct iroute_ipv6 *ir;

  ALLOC_OBJ_GC (ir, struct iroute_ipv6, &o->gc);

  if ( !get_ipv6_addr (prefix_str, &ir->network, &ir->netbits, NULL, msglevel ))
    {
      msg (msglevel, "in --iroute-ipv6 %s: Bad IPv6 prefix specification",
	   prefix_str);
      return;
    }

  ir->next = o->iroutes_ipv6;
  o->iroutes_ipv6 = ir;
}
#endif /* P2MP_SERVER */
#endif /* P2MP */

#if defined(ENABLE_HTTP_PROXY) && !defined(ENABLE_SMALL)
static void
show_http_proxy_options (const struct http_proxy_options *o)
{
  msg (D_SHOW_PARMS, "BEGIN http_proxy");
  SHOW_STR (server);
  SHOW_INT (port);
  SHOW_STR (auth_method_string);
  SHOW_STR (auth_file);
  SHOW_BOOL (retry);
  SHOW_INT (timeout);
  SHOW_STR (http_version);
  SHOW_STR (user_agent);
  msg (D_SHOW_PARMS, "END http_proxy");
}
#endif

void
options_detach (struct options *o)
{
  gc_detach (&o->gc);
  o->routes = NULL;
#ifdef ENABLE_CLIENT_NAT
  o->client_nat = NULL;
#endif
#if P2MP_SERVER
  clone_push_list(o);
#endif
}

void
rol_check_alloc (struct options *options)
{
  if (!options->routes)
    options->routes = new_route_option_list (options->max_routes, &options->gc);
}

void
rol6_check_alloc (struct options *options)
{
  if (!options->routes_ipv6)
    options->routes_ipv6 = new_route_ipv6_option_list (options->max_routes, &options->gc);
}

#ifdef ENABLE_CLIENT_NAT
static void
cnol_check_alloc (struct options *options)
{
  if (!options->client_nat)
    options->client_nat = new_client_nat_list (&options->gc);
}
#endif

#ifndef ENABLE_SMALL
static void
show_connection_entry (const struct connection_entry *o)
{
  msg (D_SHOW_PARMS, "  proto = %s", proto2ascii (o->proto, false));
  SHOW_STR (local);
  SHOW_INT (local_port);
  SHOW_STR (remote);
  SHOW_INT (remote_port);
  SHOW_BOOL (remote_float);
  SHOW_BOOL (bind_defined);
  SHOW_BOOL (bind_local);
  SHOW_INT (connect_retry_seconds);
  SHOW_INT (connect_timeout);
  SHOW_INT (connect_retry_max);

#ifdef ENABLE_HTTP_PROXY
  if (o->http_proxy_options)
    show_http_proxy_options (o->http_proxy_options);
#endif
#ifdef ENABLE_SOCKS
  SHOW_STR (socks_proxy_server);
  SHOW_INT (socks_proxy_port);
  SHOW_BOOL (socks_proxy_retry);
#endif
  SHOW_INT (tun_mtu);
  SHOW_BOOL (tun_mtu_defined);
  SHOW_INT (link_mtu);
  SHOW_BOOL (link_mtu_defined);
  SHOW_INT (tun_mtu_extra);
  SHOW_BOOL (tun_mtu_extra_defined);

  SHOW_INT (mtu_discover_type);

#ifdef ENABLE_FRAGMENT
  SHOW_INT (fragment);
#endif
  SHOW_INT (mssfix);

#ifdef ENABLE_OCC
  SHOW_INT (explicit_exit_notification);
#endif
}


static void
show_connection_entries (const struct options *o)
{
  msg (D_SHOW_PARMS, "Connection profiles [default]:");
  show_connection_entry (&o->ce);
 if (o->connection_list)
   {
     const struct connection_list *l = o->connection_list;
     int i;
     for (i = 0; i < l->len; ++i)
       {
	 msg (D_SHOW_PARMS, "Connection profiles [%d]:", i);
	 show_connection_entry (l->array[i]);
       }
   }
  msg (D_SHOW_PARMS, "Connection profiles END");
}

#endif

void
show_settings (const struct options *o)
{
#ifndef ENABLE_SMALL
  msg (D_SHOW_PARMS, "Current Parameter Settings:");

  SHOW_STR (config);
  
  SHOW_INT (mode);

#ifdef ENABLE_FEATURE_TUN_PERSIST
  SHOW_BOOL (persist_config);
  SHOW_INT (persist_mode);
#endif

#ifdef ENABLE_CRYPTO
  SHOW_BOOL (show_ciphers);
  SHOW_BOOL (show_digests);
  SHOW_BOOL (show_engines);
  SHOW_BOOL (genkey);
#ifdef ENABLE_SSL
  SHOW_STR (key_pass_file);
  SHOW_BOOL (show_tls_ciphers);
#endif
#endif

  show_connection_entries (o);

  SHOW_BOOL (remote_random);

  SHOW_STR (ipchange);
  SHOW_STR (dev);
  SHOW_STR (dev_type);
  SHOW_STR (dev_node);
  SHOW_STR (lladdr);
  SHOW_INT (topology);
  SHOW_BOOL (tun_ipv6);
  SHOW_STR (ifconfig_local);
  SHOW_STR (ifconfig_remote_netmask);
  SHOW_BOOL (ifconfig_noexec);
  SHOW_BOOL (ifconfig_nowarn);
  SHOW_STR (ifconfig_ipv6_local);
  SHOW_INT (ifconfig_ipv6_netbits);
  SHOW_STR (ifconfig_ipv6_remote);

#ifdef ENABLE_FEATURE_SHAPER
  SHOW_INT (shaper);
#endif
#ifdef ENABLE_OCC
  SHOW_INT (mtu_test);
#endif

  SHOW_BOOL (mlock);

  SHOW_INT (keepalive_ping);
  SHOW_INT (keepalive_timeout);
  SHOW_INT (inactivity_timeout);
  SHOW_INT (ping_send_timeout);
  SHOW_INT (ping_rec_timeout);
  SHOW_INT (ping_rec_timeout_action);
  SHOW_BOOL (ping_timer_remote);
  SHOW_INT (remap_sigusr1);
  SHOW_BOOL (persist_tun);
  SHOW_BOOL (persist_local_ip);
  SHOW_BOOL (persist_remote_ip);
  SHOW_BOOL (persist_key);

#if PASSTOS_CAPABILITY
  SHOW_BOOL (passtos);
#endif

  SHOW_INT (resolve_retry_seconds);

  SHOW_STR (username);
  SHOW_STR (groupname);
  SHOW_STR (chroot_dir);
  SHOW_STR (cd_dir);
#ifdef ENABLE_SELINUX
  SHOW_STR (selinux_context);
#endif
  SHOW_STR (writepid);
  SHOW_STR (up_script);
  SHOW_STR (down_script);
  SHOW_BOOL (down_pre);
  SHOW_BOOL (up_restart);
  SHOW_BOOL (up_delay);
  SHOW_BOOL (daemon);
  SHOW_INT (inetd);
  SHOW_BOOL (log);
  SHOW_BOOL (suppress_timestamps);
  SHOW_INT (nice);
  SHOW_INT (verbosity);
  SHOW_INT (mute);
#ifdef ENABLE_DEBUG
  SHOW_INT (gremlin);
#endif
  SHOW_STR (status_file);
  SHOW_INT (status_file_version);
  SHOW_INT (status_file_update_freq);

#ifdef ENABLE_OCC
  SHOW_BOOL (occ);
#endif
  SHOW_INT (rcvbuf);
  SHOW_INT (sndbuf);
#if defined(TARGET_LINUX) && HAVE_DECL_SO_MARK
  SHOW_INT (mark);
#endif
  SHOW_INT (sockflags);

  SHOW_BOOL (fast_io);

#ifdef ENABLE_LZO
  SHOW_INT (lzo);
#endif

  SHOW_STR (route_script);
  SHOW_STR (route_default_gateway);
  SHOW_INT (route_default_metric);
  SHOW_BOOL (route_noexec);
  SHOW_INT (route_delay);
  SHOW_INT (route_delay_window);
  SHOW_BOOL (route_delay_defined);
  SHOW_BOOL (route_nopull);
  SHOW_BOOL (route_gateway_via_dhcp);
  SHOW_INT (max_routes);
  SHOW_BOOL (allow_pull_fqdn);
  if (o->routes)
    print_route_options (o->routes, D_SHOW_PARMS);
  
#ifdef ENABLE_CLIENT_NAT
  if (o->client_nat)
    print_client_nat_list(o->client_nat, D_SHOW_PARMS);
#endif

#ifdef ENABLE_MANAGEMENT
  SHOW_STR (management_addr);
  SHOW_INT (management_port);
  SHOW_STR (management_user_pass);
  SHOW_INT (management_log_history_cache);
  SHOW_INT (management_echo_buffer_size);
  SHOW_STR (management_write_peer_info_file);
  SHOW_STR (management_client_user);
  SHOW_STR (management_client_group);
  SHOW_INT (management_flags);
#endif
#ifdef ENABLE_PLUGIN
  if (o->plugin_list)
    plugin_option_list_print (o->plugin_list, D_SHOW_PARMS);
#endif

#ifdef ENABLE_CRYPTO
  SHOW_STR (shared_secret_file);
  SHOW_INT (key_direction);
  SHOW_BOOL (ciphername_defined);
  SHOW_STR (ciphername);
  SHOW_BOOL (authname_defined);
  SHOW_STR (authname);
  SHOW_STR (prng_hash);
  SHOW_INT (prng_nonce_secret_len);
  SHOW_INT (keysize);
#ifndef ENABLE_CRYPTO_POLARSSL
  SHOW_BOOL (engine);
#endif /* ENABLE_CRYPTO_POLARSSL */
  SHOW_BOOL (replay);
  SHOW_BOOL (mute_replay_warnings);
  SHOW_INT (replay_window);
  SHOW_INT (replay_time);
  SHOW_STR (packet_id_file);
  SHOW_BOOL (use_iv);
  SHOW_BOOL (test_crypto);
#ifdef ENABLE_PREDICTION_RESISTANCE
  SHOW_BOOL (use_prediction_resistance);
#endif

#ifdef ENABLE_SSL
  SHOW_BOOL (tls_server);
  SHOW_BOOL (tls_client);
  SHOW_INT (key_method);
  SHOW_STR (ca_file);
  SHOW_STR (ca_path);
  SHOW_STR (dh_file);
  SHOW_STR (cert_file);

#ifdef MANAGMENT_EXTERNAL_KEY
  if((o->management_flags & MF_EXTERNAL_KEY))
	SHOW_PARM ("priv_key_file","EXTERNAL_PRIVATE_KEY","%s");
  else
#endif
  SHOW_STR (priv_key_file);
#ifndef ENABLE_CRYPTO_POLARSSL
  SHOW_STR (pkcs12_file);
#endif
#ifdef ENABLE_CRYPTOAPI
  SHOW_STR (cryptoapi_cert);
#endif
  SHOW_STR (cipher_list);
  SHOW_STR (tls_verify);
  SHOW_STR (tls_export_cert);
  SHOW_INT (verify_x509_type);
  SHOW_STR (verify_x509_name);
  SHOW_STR (crl_file);
  SHOW_INT (ns_cert_type);
  {
    int i;
    for (i=0;i<MAX_PARMS;i++)
      SHOW_INT (remote_cert_ku[i]);
  }
  SHOW_STR (remote_cert_eku);
  SHOW_INT (ssl_flags);

  SHOW_INT (tls_timeout);

  SHOW_INT (renegotiate_bytes);
  SHOW_INT (renegotiate_packets);
  SHOW_INT (renegotiate_seconds);

  SHOW_INT (handshake_window);
  SHOW_INT (transition_window);

  SHOW_BOOL (single_session);
#ifdef ENABLE_PUSH_PEER_INFO
  SHOW_BOOL (push_peer_info);
#endif
  SHOW_BOOL (tls_exit);

  SHOW_STR (tls_auth_file);
#endif
#endif

#ifdef ENABLE_PKCS11
  {
    int i;
    for (i=0;i<MAX_PARMS && o->pkcs11_providers[i] != NULL;i++)
      SHOW_PARM (pkcs11_providers, o->pkcs11_providers[i], "%s");
  }
  {
    int i;
    for (i=0;i<MAX_PARMS;i++)
      SHOW_PARM (pkcs11_protected_authentication, o->pkcs11_protected_authentication[i] ? "ENABLED" : "DISABLED", "%s");
  }
  {
    int i;
    for (i=0;i<MAX_PARMS;i++)
      SHOW_PARM (pkcs11_private_mode, o->pkcs11_private_mode[i], "%08x");
  }
  {
    int i;
    for (i=0;i<MAX_PARMS;i++)
      SHOW_PARM (pkcs11_cert_private, o->pkcs11_cert_private[i] ? "ENABLED" : "DISABLED", "%s");
  }
  SHOW_INT (pkcs11_pin_cache_period);
  SHOW_STR (pkcs11_id);
  SHOW_BOOL (pkcs11_id_management);
#endif			/* ENABLE_PKCS11 */

#if P2MP
  show_p2mp_parms (o);
#endif

#ifdef WIN32
  SHOW_BOOL (show_net_up);
  SHOW_INT (route_method);
  show_tuntap_options (&o->tuntap_options);
#endif
#endif
}

#undef SHOW_PARM
#undef SHOW_STR
#undef SHOW_INT
#undef SHOW_BOOL

#if HTTP_PROXY_OVERRIDE

static struct http_proxy_options *
parse_http_proxy_override (const char *server,
			   const char *port,
			   const char *flags,
			   const int msglevel,
			   struct gc_arena *gc)
{
  if (server && port)
    {
      struct http_proxy_options *ho;
      const int int_port = atoi(port);

      if (!legal_ipv4_port (int_port))
	{
	  msg (msglevel, "Bad http-proxy port number: %s", port);
	  return NULL;
	}

      ALLOC_OBJ_CLEAR_GC (ho, struct http_proxy_options, gc);
      ho->server = string_alloc(server, gc);
      ho->port = int_port;
      ho->retry = true;
      ho->timeout = 5;
      if (flags && !strcmp(flags, "nct"))
	ho->auth_retry = PAR_NCT;
      else
	ho->auth_retry = PAR_ALL;
      ho->http_version = "1.0";
      ho->user_agent = "OpenVPN-Autoproxy/1.0";
      return ho;
    }
  else
    return NULL;
}

void
options_postprocess_http_proxy_override (struct options *o)
{
  const struct connection_list *l = o->connection_list;
   if (l)
    {
      int i;
      bool succeed = false;
      for (i = 0; i < l->len; ++i)
	{
	  struct connection_entry *ce = l->array[i];
	  if (ce->proto == PROTO_TCPv4_CLIENT || ce->proto == PROTO_TCPv4)
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
	      if (ce->proto == PROTO_UDPv4)
		{
		  ce->flags |= CE_DISABLED;
		}
	    }
	}
      else
        msg (M_WARN, "Note: option http-proxy-override ignored because no TCP-based connection profiles are defined");
    }
}

#endif

static struct connection_list *
alloc_connection_list_if_undef (struct options *options)
{
  if (!options->connection_list)
    ALLOC_OBJ_CLEAR_GC (options->connection_list, struct connection_list, &options->gc);
  return options->connection_list;
}

static struct connection_entry *
alloc_connection_entry (struct options *options, const int msglevel)
{
  struct connection_list *l = alloc_connection_list_if_undef (options);
  struct connection_entry *e;

  if (l->len >= CONNECTION_LIST_SIZE)
    {
      msg (msglevel, "Maximum number of 'connection' options (%d) exceeded", CONNECTION_LIST_SIZE);
      return NULL;
    }
  ALLOC_OBJ_GC (e, struct connection_entry, &options->gc);
  l->array[l->len++] = e;
  return e;
}

static struct remote_list *
alloc_remote_list_if_undef (struct options *options)
{
  if (!options->remote_list)
    ALLOC_OBJ_CLEAR_GC (options->remote_list, struct remote_list, &options->gc);
  return options->remote_list;
}

static struct remote_entry *
alloc_remote_entry (struct options *options, const int msglevel)
{
  struct remote_list *l = alloc_remote_list_if_undef (options);
  struct remote_entry *e;

  if (l->len >= CONNECTION_LIST_SIZE)
    {
      msg (msglevel, "Maximum number of 'remote' options (%d) exceeded", CONNECTION_LIST_SIZE);
      return NULL;
    }
  ALLOC_OBJ_GC (e, struct remote_entry, &options->gc);
  l->array[l->len++] = e;
  return e;
}

void
connection_entry_load_re (struct connection_entry *ce, const struct remote_entry *re)
{
  if (re->remote)
    ce->remote = re->remote;
  if (re->remote_port >= 0)
    ce->remote_port = re->remote_port;
  if (re->proto >= 0)
    ce->proto = re->proto;
}

static void
options_postprocess_verify_ce (const struct options *options, const struct connection_entry *ce)
{
  struct options defaults;
  int dev = DEV_TYPE_UNDEF;
  bool pull = false;

  init_options (&defaults, true);

#ifdef ENABLE_CRYPTO
  if (options->test_crypto)
    {
      notnull (options->shared_secret_file, "key file (--secret)");
    }
  else
#endif
    notnull (options->dev, "TUN/TAP device (--dev)");

  /*
   * Get tun/tap/null device type
   */
  dev = dev_type_enum (options->dev, options->dev_type);

  /*
   * If "proto tcp" is specified, make sure we know whether it is
   * tcp-client or tcp-server.
   */
  if (ce->proto == PROTO_TCPv4)
    msg (M_USAGE, "--proto tcp is ambiguous in this context.  Please specify --proto tcp-server or --proto tcp-client");
  if (ce->proto == PROTO_TCPv6)
    msg (M_USAGE, "--proto tcp6 is ambiguous in this context.  Please specify --proto tcp6-server or --proto tcp6-client");

  /*
   * Sanity check on daemon/inetd modes
   */

  if (options->daemon && options->inetd)
    msg (M_USAGE, "only one of --daemon or --inetd may be specified");

  if (options->inetd && (ce->local || ce->remote))
    msg (M_USAGE, "--local or --remote cannot be used with --inetd");

  if (options->inetd && ce->proto == PROTO_TCPv4_CLIENT)
    msg (M_USAGE, "--proto tcp-client cannot be used with --inetd");

  if (options->inetd == INETD_NOWAIT && ce->proto != PROTO_TCPv4_SERVER)
    msg (M_USAGE, "--inetd nowait can only be used with --proto tcp-server");

  if (options->inetd == INETD_NOWAIT
#if defined(ENABLE_CRYPTO) && defined(ENABLE_SSL)
      && !(options->tls_server || options->tls_client)
#endif
      )
    msg (M_USAGE, "--inetd nowait can only be used in TLS mode");

  if (options->inetd == INETD_NOWAIT && dev != DEV_TYPE_TAP)
    msg (M_USAGE, "--inetd nowait only makes sense in --dev tap mode");


  if (options->lladdr && dev != DEV_TYPE_TAP)
    msg (M_USAGE, "--lladdr can only be used in --dev tap mode");
 
  /*
   * Sanity check on TCP mode options
   */

  if (ce->connect_retry_defined && ce->proto != PROTO_TCPv4_CLIENT
      && ce->proto != PROTO_TCPv6_CLIENT)
    msg (M_USAGE, "--connect-retry doesn't make sense unless also used with "
	 "--proto tcp-client or tcp6-client");

  if (ce->connect_timeout_defined && ce->proto != PROTO_TCPv4_CLIENT
      && ce->proto != PROTO_TCPv6_CLIENT)
    msg (M_USAGE, "--connect-timeout doesn't make sense unless also used with "
	 "--proto tcp-client or tcp6-client");

  /*
   * Sanity check on MTU parameters
   */
  if (options->ce.tun_mtu_defined && options->ce.link_mtu_defined)
    msg (M_USAGE, "only one of --tun-mtu or --link-mtu may be defined (note that --ifconfig implies --link-mtu %d)", LINK_MTU_DEFAULT);

#ifdef ENABLE_OCC
  if (!proto_is_udp(ce->proto) && options->mtu_test)
    msg (M_USAGE, "--mtu-test only makes sense with --proto udp");
#endif

  /* will we be pulling options from server? */
#if P2MP
  pull = options->pull;
#endif

  /*
   * Sanity check on --local, --remote, and --ifconfig
   */

  if (proto_is_net(ce->proto)
      && string_defined_equal (ce->local, ce->remote)
      && ce->local_port == ce->remote_port)
    msg (M_USAGE, "--remote and --local addresses are the same");
  
  if (string_defined_equal (ce->remote, options->ifconfig_local)
      || string_defined_equal (ce->remote, options->ifconfig_remote_netmask))
    msg (M_USAGE, "--local and --remote addresses must be distinct from --ifconfig addresses");

  if (string_defined_equal (ce->local, options->ifconfig_local)
      || string_defined_equal (ce->local, options->ifconfig_remote_netmask))
    msg (M_USAGE, "--local addresses must be distinct from --ifconfig addresses");

  if (string_defined_equal (options->ifconfig_local, options->ifconfig_remote_netmask))
    msg (M_USAGE, "local and remote/netmask --ifconfig addresses must be different");

  if (ce->bind_defined && !ce->bind_local)
    msg (M_USAGE, "--bind and --nobind can't be used together");

  if (ce->local && !ce->bind_local)
    msg (M_USAGE, "--local and --nobind don't make sense when used together");

  if (ce->local_port_defined && !ce->bind_local)
    msg (M_USAGE, "--lport and --nobind don't make sense when used together");

  if (!ce->remote && !ce->bind_local)
    msg (M_USAGE, "--nobind doesn't make sense unless used with --remote");

  /*
   * Check for consistency of management options
   */
#ifdef ENABLE_MANAGEMENT
  if (!options->management_addr &&
      (options->management_flags
       || options->management_write_peer_info_file
       || options->management_log_history_cache != defaults.management_log_history_cache))
    msg (M_USAGE, "--management is not specified, however one or more options which modify the behavior of --management were specified");

  if ((options->management_client_user || options->management_client_group)
      && !(options->management_flags & MF_UNIX_SOCK))
    msg (M_USAGE, "--management-client-(user|group) can only be used on unix domain sockets");
#endif

  /*
   * Windows-specific options.
   */

#ifdef WIN32
      if (dev == DEV_TYPE_TUN && !(pull || (options->ifconfig_local && options->ifconfig_remote_netmask)))
	msg (M_USAGE, "On Windows, --ifconfig is required when --dev tun is used");

      if ((options->tuntap_options.ip_win32_defined)
	  && !(pull || (options->ifconfig_local && options->ifconfig_remote_netmask)))
	msg (M_USAGE, "On Windows, --ip-win32 doesn't make sense unless --ifconfig is also used");

      if (options->tuntap_options.dhcp_options
	  && options->tuntap_options.ip_win32_type != IPW32_SET_DHCP_MASQ
	  && options->tuntap_options.ip_win32_type != IPW32_SET_ADAPTIVE)
	msg (M_USAGE, "--dhcp-options requires --ip-win32 dynamic or adaptive");
#endif

  /*
   * Check that protocol options make sense.
   */

#ifdef ENABLE_FRAGMENT
  if (!proto_is_udp(ce->proto) && ce->fragment)
    msg (M_USAGE, "--fragment can only be used with --proto udp");
#endif

#ifdef ENABLE_OCC
  if (!proto_is_udp(ce->proto) && ce->explicit_exit_notification)
    msg (M_USAGE, "--explicit-exit-notify can only be used with --proto udp");
#endif

  if (!ce->remote && (ce->proto == PROTO_TCPv4_CLIENT 
		      || ce->proto == PROTO_TCPv6_CLIENT))
    msg (M_USAGE, "--remote MUST be used in TCP Client mode");

#ifdef ENABLE_HTTP_PROXY
  if ((ce->http_proxy_options) && ce->proto != PROTO_TCPv4_CLIENT)
    msg (M_USAGE, "--http-proxy MUST be used in TCP Client mode (i.e. --proto tcp-client)");
  if ((ce->http_proxy_options) && !ce->http_proxy_options->server)
    msg (M_USAGE, "--http-proxy not specified but other http proxy options present");
#endif

#if defined(ENABLE_HTTP_PROXY) && defined(ENABLE_SOCKS)
  if (ce->http_proxy_options && ce->socks_proxy_server)
    msg (M_USAGE, "--http-proxy can not be used together with --socks-proxy");
#endif

#ifdef ENABLE_SOCKS
  if (ce->socks_proxy_server && ce->proto == PROTO_TCPv4_SERVER)
    msg (M_USAGE, "--socks-proxy can not be used in TCP Server mode");
#endif

  if ((ce->proto == PROTO_TCPv4_SERVER || ce->proto == PROTO_TCPv6_SERVER)
      && connection_list_defined (options))
    msg (M_USAGE, "TCP server mode allows at most one --remote address");

#if P2MP_SERVER

  /*
   * Check consistency of --mode server options.
   */
  if (options->mode == MODE_SERVER)
    {
      if (!(dev == DEV_TYPE_TUN || dev == DEV_TYPE_TAP))
	msg (M_USAGE, "--mode server only works with --dev tun or --dev tap");
      if (options->pull)
	msg (M_USAGE, "--pull cannot be used with --mode server");
      if (!(proto_is_udp(ce->proto) || ce->proto == PROTO_TCPv4_SERVER
	    || ce->proto == PROTO_TCPv6_SERVER))
	msg (M_USAGE, "--mode server currently only supports "
	     "--proto udp or --proto tcp-server or proto tcp6-server");
#if PORT_SHARE
      if ((options->port_share_host || options->port_share_port) && 
	  (ce->proto != PROTO_TCPv4_SERVER && ce->proto != PROTO_TCPv6_SERVER))
	msg (M_USAGE, "--port-share only works in TCP server mode "
	     "(--proto tcp-server or tcp6-server)");
#endif
      if (!options->tls_server)
	msg (M_USAGE, "--mode server requires --tls-server");
      if (ce->remote)
	msg (M_USAGE, "--remote cannot be used with --mode server");
      if (!ce->bind_local)
	msg (M_USAGE, "--nobind cannot be used with --mode server");
#ifdef ENABLE_HTTP_PROXY
      if (ce->http_proxy_options)
	msg (M_USAGE, "--http-proxy cannot be used with --mode server");
#endif
#ifdef ENABLE_SOCKS
      if (ce->socks_proxy_server)
	msg (M_USAGE, "--socks-proxy cannot be used with --mode server");
#endif
      if (options->connection_list)
	msg (M_USAGE, "<connection> cannot be used with --mode server");
#if 0
      if (options->tun_ipv6)
	msg (M_USAGE, "--tun-ipv6 cannot be used with --mode server");
#endif
      if (options->shaper)
	msg (M_USAGE, "--shaper cannot be used with --mode server");
      if (options->inetd)
	msg (M_USAGE, "--inetd cannot be used with --mode server");
      if (options->ipchange)
	msg (M_USAGE, "--ipchange cannot be used with --mode server (use --client-connect instead)");
      if (!(proto_is_dgram(ce->proto) || ce->proto == PROTO_TCPv4_SERVER
	    || ce->proto == PROTO_TCPv6_SERVER))
	msg (M_USAGE, "--mode server currently only supports "
	     "--proto udp or --proto tcp-server or --proto tcp6-server");
      if (!proto_is_udp(ce->proto) && (options->cf_max || options->cf_per))
	msg (M_USAGE, "--connect-freq only works with --mode server --proto udp.  Try --max-clients instead.");
      if (!(dev == DEV_TYPE_TAP || (dev == DEV_TYPE_TUN && options->topology == TOP_SUBNET)) && options->ifconfig_pool_netmask)
	msg (M_USAGE, "The third parameter to --ifconfig-pool (netmask) is only valid in --dev tap mode");
#ifdef ENABLE_OCC
      if (ce->explicit_exit_notification)
	msg (M_USAGE, "--explicit-exit-notify cannot be used with --mode server");
#endif
      if (options->routes && (options->routes->flags & RG_ENABLE))
	msg (M_USAGE, "--redirect-gateway cannot be used with --mode server (however --push \"redirect-gateway\" is fine)");
      if (options->route_delay_defined)
	msg (M_USAGE, "--route-delay cannot be used with --mode server");
      if (options->up_delay)
	msg (M_USAGE, "--up-delay cannot be used with --mode server");
      if (!options->ifconfig_pool_defined && options->ifconfig_pool_persist_filename)
	msg (M_USAGE, "--ifconfig-pool-persist must be used with --ifconfig-pool");
      if (options->ifconfig_ipv6_pool_defined && !options->ifconfig_ipv6_local )
	msg (M_USAGE, "--ifconfig-ipv6-pool needs --ifconfig-ipv6");
      if (options->ifconfig_ipv6_local && !options->tun_ipv6 )
	msg (M_INFO, "Warning: --ifconfig-ipv6 without --tun-ipv6 will not do IPv6");

      if (options->auth_user_pass_file)
	msg (M_USAGE, "--auth-user-pass cannot be used with --mode server (it should be used on the client side only)");
      if (options->ccd_exclusive && !options->client_config_dir)
	msg (M_USAGE, "--ccd-exclusive must be used with --client-config-dir");
      if (options->key_method != 2)
	msg (M_USAGE, "--mode server requires --key-method 2");

	{
	  const bool ccnr = (options->auth_user_pass_verify_script
			     || PLUGIN_OPTION_LIST (options)
			     || MAN_CLIENT_AUTH_ENABLED (options));
	  const char *postfix = "must be used with --management-client-auth, an --auth-user-pass-verify script, or plugin";
	  if ((options->ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED) && !ccnr)
	    msg (M_USAGE, "--client-cert-not-required %s", postfix);
	  if ((options->ssl_flags & SSLF_USERNAME_AS_COMMON_NAME) && !ccnr)
	    msg (M_USAGE, "--username-as-common-name %s", postfix);
	  if ((options->ssl_flags & SSLF_AUTH_USER_PASS_OPTIONAL) && !ccnr)
	    msg (M_USAGE, "--auth-user-pass-optional %s", postfix);
	}
    }
  else
    {
      /*
       * When not in server mode, err if parameters are
       * specified which require --mode server.
       */
      if (options->ifconfig_pool_defined || options->ifconfig_pool_persist_filename)
	msg (M_USAGE, "--ifconfig-pool/--ifconfig-pool-persist requires --mode server");
      if (options->ifconfig_ipv6_pool_defined)
	msg (M_USAGE, "--ifconfig-ipv6-pool requires --mode server");
      if (options->real_hash_size != defaults.real_hash_size
	  || options->virtual_hash_size != defaults.virtual_hash_size)
	msg (M_USAGE, "--hash-size requires --mode server");
      if (options->learn_address_script)
	msg (M_USAGE, "--learn-address requires --mode server");
      if (options->client_connect_script)
	msg (M_USAGE, "--client-connect requires --mode server");
      if (options->client_disconnect_script)
	msg (M_USAGE, "--client-disconnect requires --mode server");
      if (options->client_config_dir || options->ccd_exclusive)
	msg (M_USAGE, "--client-config-dir/--ccd-exclusive requires --mode server");
      if (options->enable_c2c)
	msg (M_USAGE, "--client-to-client requires --mode server");
      if (options->duplicate_cn)
	msg (M_USAGE, "--duplicate-cn requires --mode server");
      if (options->cf_max || options->cf_per)
	msg (M_USAGE, "--connect-freq requires --mode server");
      if (options->ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED)
	msg (M_USAGE, "--client-cert-not-required requires --mode server");
      if (options->ssl_flags & SSLF_USERNAME_AS_COMMON_NAME)
	msg (M_USAGE, "--username-as-common-name requires --mode server");
      if (options->ssl_flags & SSLF_AUTH_USER_PASS_OPTIONAL)
	msg (M_USAGE, "--auth-user-pass-optional requires --mode server");
      if (options->ssl_flags & SSLF_OPT_VERIFY)
	msg (M_USAGE, "--opt-verify requires --mode server");
      if (options->server_flags & SF_TCP_NODELAY_HELPER)
	msg (M_WARN, "WARNING: setting tcp-nodelay on the client side will not "
             "affect the server. To have TCP_NODELAY in both direction use "
             "tcp-nodelay in the server configuration instead.");
      if (options->auth_user_pass_verify_script)
	msg (M_USAGE, "--auth-user-pass-verify requires --mode server");
#if PORT_SHARE
      if (options->port_share_host || options->port_share_port)
	msg (M_USAGE, "--port-share requires TCP server mode (--mode server --proto tcp-server)");
#endif

      if (options->stale_routes_check_interval)
        msg (M_USAGE, "--stale-routes-check requires --mode server");
      if (compat_flag (COMPAT_FLAG_QUERY | COMPAT_NO_NAME_REMAPPING))
        msg (M_USAGE, "--compat-x509-names no-remapping requires --mode server");
    }
#endif /* P2MP_SERVER */

#ifdef ENABLE_CRYPTO

  /*
   * Check consistency of replay options
   */
  if ((!proto_is_udp(ce->proto))
      && (options->replay_window != defaults.replay_window
	  || options->replay_time != defaults.replay_time))
    msg (M_USAGE, "--replay-window only makes sense with --proto udp");

  if (!options->replay
      && (options->replay_window != defaults.replay_window
	  || options->replay_time != defaults.replay_time))
    msg (M_USAGE, "--replay-window doesn't make sense when replay protection is disabled with --no-replay");

  /*
   * SSL/TLS mode sanity checks.
   */

#ifdef ENABLE_SSL
  if (options->tls_server + options->tls_client +
      (options->shared_secret_file != NULL) > 1)
    msg (M_USAGE, "specify only one of --tls-server, --tls-client, or --secret");

  if (options->tls_server)
    {
      notnull (options->dh_file, "DH file (--dh)");
    }
  if (options->tls_server || options->tls_client)
    {
#ifdef ENABLE_PKCS11
      if (options->pkcs11_providers[0])
       {
        notnull (options->ca_file, "CA file (--ca)");

	if (options->pkcs11_id_management && options->pkcs11_id != NULL)
	  msg(M_USAGE, "Parameter --pkcs11-id cannot be used when --pkcs11-id-management is also specified.");
	if (!options->pkcs11_id_management && options->pkcs11_id == NULL)
	  msg(M_USAGE, "Parameter --pkcs11-id or --pkcs11-id-management should be specified.");
	if (options->cert_file)
	  msg(M_USAGE, "Parameter --cert cannot be used when --pkcs11-provider is also specified.");
	if (options->priv_key_file)
	  msg(M_USAGE, "Parameter --key cannot be used when --pkcs11-provider is also specified.");
#ifdef MANAGMENT_EXTERNAL_KEY
	if (options->management_flags & MF_EXTERNAL_KEY)
	  msg(M_USAGE, "Parameter --management-external-key cannot be used when --pkcs11-provider is also specified.");
#endif
	if (options->pkcs12_file)
	  msg(M_USAGE, "Parameter --pkcs12 cannot be used when --pkcs11-provider is also specified.");
#ifdef ENABLE_CRYPTOAPI
	if (options->cryptoapi_cert)
	  msg(M_USAGE, "Parameter --cryptoapicert cannot be used when --pkcs11-provider is also specified.");
#endif
       }
      else
#endif
#ifdef MANAGMENT_EXTERNAL_KEY
	 if((options->management_flags & MF_EXTERNAL_KEY) && options->priv_key_file)
	   {
		 msg (M_USAGE, "--key and --management-external-key are mutually exclusive");
	   }
	 else
#endif
#ifdef ENABLE_CRYPTOAPI
     if (options->cryptoapi_cert)
	{
	  if ((!(options->ca_file)) && (!(options->ca_path)))
	    msg(M_USAGE, "You must define CA file (--ca) or CA path (--capath)");
          if (options->cert_file)
	    msg(M_USAGE, "Parameter --cert cannot be used when --cryptoapicert is also specified.");
          if (options->priv_key_file)
	    msg(M_USAGE, "Parameter --key cannot be used when --cryptoapicert is also specified.");
          if (options->pkcs12_file)
	    msg(M_USAGE, "Parameter --pkcs12 cannot be used when --cryptoapicert is also specified.");
#ifdef MANAGMENT_EXTERNAL_KEY
          if (options->management_flags & MF_EXTERNAL_KEY)
	    msg(M_USAGE, "Parameter --management-external-key cannot be used when --cryptoapicert is also specified.");
#endif
	}
      else
#endif
      if (options->pkcs12_file)
        {
#ifdef ENABLE_CRYPTO_POLARSSL
	  msg(M_USAGE, "Parameter --pkcs12 cannot be used with the PolarSSL version version of OpenVPN.");
#else
          if (options->ca_path)
	    msg(M_USAGE, "Parameter --capath cannot be used when --pkcs12 is also specified.");
          if (options->cert_file)
	    msg(M_USAGE, "Parameter --cert cannot be used when --pkcs12 is also specified.");
          if (options->priv_key_file)
	    msg(M_USAGE, "Parameter --key cannot be used when --pkcs12 is also specified.");
#ifdef MANAGMENT_EXTERNAL_KEY
          if (options->management_flags & MF_EXTERNAL_KEY)
	    msg(M_USAGE, "Parameter --external-management-key cannot be used when --pkcs12 is also specified.");
#endif
#endif
        }
      else
        {
#ifdef ENABLE_CRYPTO_POLARSSL
	  if (!(options->ca_file))
	    msg(M_USAGE, "You must define CA file (--ca)");
          if (options->ca_path)
            msg(M_USAGE, "Parameter --capath cannot be used with the PolarSSL version version of OpenVPN.");
#else
	  if ((!(options->ca_file)) && (!(options->ca_path)))
	    msg(M_USAGE, "You must define CA file (--ca) or CA path (--capath)");
#endif
	  if (pull)
	    {

	      const int sum = (options->cert_file != NULL) +
#ifdef MANAGMENT_EXTERNAL_KEY
			((options->priv_key_file != NULL) || (options->management_flags & MF_EXTERNAL_KEY));
#else
		    (options->priv_key_file != NULL);
#endif


	      if (sum == 0)
		{
#if P2MP
		  if (!options->auth_user_pass_file)
#endif
		    msg (M_USAGE, "No client-side authentication method is specified.  You must use either --cert/--key, --pkcs12, or --auth-user-pass");
		}
	      else if (sum == 2)
		;
	      else
		{
		  msg (M_USAGE, "If you use one of --cert or --key, you must use them both");
		}
	    }
	  else
	    {
	      notnull (options->cert_file, "certificate file (--cert) or PKCS#12 file (--pkcs12)");
#ifdef MANAGMENT_EXTERNAL_KEY
          if (!(options->management_flags & MF_EXTERNAL_KEY))
#endif
	      notnull (options->priv_key_file, "private key file (--key) or PKCS#12 file (--pkcs12)");
	    }
	}
    }
  else
    {
      /*
       * Make sure user doesn't specify any TLS options
       * when in non-TLS mode.
       */

#define MUST_BE_UNDEF(parm) if (options->parm != defaults.parm) msg (M_USAGE, err, #parm);

      const char err[] = "Parameter %s can only be specified in TLS-mode, i.e. where --tls-server or --tls-client is also specified.";

      MUST_BE_UNDEF (ca_file);
      MUST_BE_UNDEF (ca_path);
      MUST_BE_UNDEF (dh_file);
      MUST_BE_UNDEF (cert_file);
      MUST_BE_UNDEF (priv_key_file);
#ifndef ENABLE_CRYPTO_POLARSSL
      MUST_BE_UNDEF (pkcs12_file);
#endif
      MUST_BE_UNDEF (cipher_list);
      MUST_BE_UNDEF (tls_verify);
      MUST_BE_UNDEF (tls_export_cert);
      MUST_BE_UNDEF (verify_x509_name);
      MUST_BE_UNDEF (tls_timeout);
      MUST_BE_UNDEF (renegotiate_bytes);
      MUST_BE_UNDEF (renegotiate_packets);
      MUST_BE_UNDEF (renegotiate_seconds);
      MUST_BE_UNDEF (handshake_window);
      MUST_BE_UNDEF (transition_window);
      MUST_BE_UNDEF (tls_auth_file);
      MUST_BE_UNDEF (single_session);
#ifdef ENABLE_PUSH_PEER_INFO
      MUST_BE_UNDEF (push_peer_info);
#endif
      MUST_BE_UNDEF (tls_exit);
      MUST_BE_UNDEF (crl_file);
      MUST_BE_UNDEF (key_method);
      MUST_BE_UNDEF (ns_cert_type);
      MUST_BE_UNDEF (remote_cert_ku[0]);
      MUST_BE_UNDEF (remote_cert_eku);
#ifdef ENABLE_PKCS11
      MUST_BE_UNDEF (pkcs11_providers[0]);
      MUST_BE_UNDEF (pkcs11_private_mode[0]);
      MUST_BE_UNDEF (pkcs11_id);
      MUST_BE_UNDEF (pkcs11_id_management);
#endif
#if P2MP
      MUST_BE_UNDEF (server_poll_timeout);
#endif

      if (pull)
	msg (M_USAGE, err, "--pull");
    }
#undef MUST_BE_UNDEF
#endif /* ENABLE_CRYPTO */
#endif /* ENABLE_SSL */

#if P2MP
  if (options->auth_user_pass_file && !options->pull)
    msg (M_USAGE, "--auth-user-pass requires --pull");
#endif

  uninit_options (&defaults);
}

static void
options_postprocess_mutate_ce (struct options *o, struct connection_entry *ce)
{
  const int dev = dev_type_enum (o->dev, o->dev_type);

#if P2MP_SERVER
  if (o->server_defined || o->server_bridge_defined || o->server_bridge_proxy_dhcp)
    {
      if (ce->proto == PROTO_TCPv4)
	ce->proto = PROTO_TCPv4_SERVER;
      else if (ce->proto == PROTO_TCPv6)
	ce->proto = PROTO_TCPv6_SERVER;
    }
#endif
#if P2MP
  if (o->client)
    {
      if (ce->proto == PROTO_TCPv4)
	ce->proto = PROTO_TCPv4_CLIENT;
      else if (ce->proto == PROTO_TCPv6)
	ce->proto = PROTO_TCPv6_CLIENT;
    }
#endif

  if (ce->proto == PROTO_TCPv4_CLIENT && !ce->local && !ce->local_port_defined && !ce->bind_defined)
    ce->bind_local = false;

#ifdef ENABLE_SOCKS
  if (ce->proto == PROTO_UDPv4 && ce->socks_proxy_server && !ce->local && !ce->local_port_defined && !ce->bind_defined)
    ce->bind_local = false;
#endif

  if (!ce->bind_local)
    ce->local_port = 0;

  /* if protocol forcing is enabled, disable all protocols except for the forced one */
  if (o->proto_force >= 0 && proto_is_tcp(o->proto_force) != proto_is_tcp(ce->proto))
    ce->flags |= CE_DISABLED;

  /*
   * If --mssfix is supplied without a parameter, default
   * it to --fragment value, if --fragment is specified.
   */
  if (o->ce.mssfix_default)
    {
#ifdef ENABLE_FRAGMENT
      if (ce->fragment)
	ce->mssfix = ce->fragment;
#else
      msg (M_USAGE, "--mssfix must specify a parameter");
#endif      
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

}

static void
options_postprocess_mutate_invariant (struct options *options)
{
  const int dev = dev_type_enum (options->dev, options->dev_type);

  /*
   * In forking TCP server mode, you don't need to ifconfig
   * the tap device (the assumption is that it will be bridged).
   */
  if (options->inetd == INETD_NOWAIT)
    options->ifconfig_noexec = true;

#ifdef WIN32
  if ((dev == DEV_TYPE_TUN || dev == DEV_TYPE_TAP) && !options->route_delay_defined)
    {
      if (options->mode == MODE_POINT_TO_POINT)
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
#endif

#if P2MP_SERVER
  /*
   * Check consistency of --mode server options.
   */
  if (options->mode == MODE_SERVER)
    {
#ifdef WIN32
      /*
       * We need to explicitly set --tap-sleep because
       * we do not schedule event timers in the top-level context.
       */
      options->tuntap_options.tap_sleep = 10;
      if (options->route_delay_defined && options->route_delay)
	options->tuntap_options.tap_sleep = options->route_delay;	
      options->route_delay_defined = false;
#endif
    }
#endif

#ifdef DEFAULT_PKCS11_MODULE
  /* If p11-kit is present on the system then load its p11-kit-proxy.so
     by default if the user asks for PKCS#11 without otherwise specifying
     the module to use. */
  if (!options->pkcs11_providers[0] &&
      (options->pkcs11_id || options->pkcs11_id_management))
    options->pkcs11_providers[0] = DEFAULT_PKCS11_MODULE;
#endif
}

static void
options_postprocess_verify (const struct options *o)
{
  if (o->connection_list)
    {
      int i;
      for (i = 0; i < o->connection_list->len; ++i)
	options_postprocess_verify_ce (o, o->connection_list->array[i]);
    }
  else
    options_postprocess_verify_ce (o, &o->ce);
}

static void
options_postprocess_mutate (struct options *o)
{
  /*
   * Process helper-type options which map to other, more complex
   * sequences of options.
   */
  helper_client_server (o);
  helper_keepalive (o);
  helper_tcp_nodelay (o);

  options_postprocess_mutate_invariant (o);

  if (o->remote_list && !o->connection_list)
    {
      /*
       * For compatibility with 2.0.x, map multiple --remote options
       * into connection list (connection lists added in 2.1).
       */
      if (o->remote_list->len > 1 || o->force_connection_list)
	{
	  const struct remote_list *rl = o->remote_list;
	  int i;
	  for (i = 0; i < rl->len; ++i)
	    {
	      const struct remote_entry *re = rl->array[i];
	      struct connection_entry ce = o->ce;
	      struct connection_entry *ace;

	      ASSERT (re->remote);
	      connection_entry_load_re (&ce, re);
	      ace = alloc_connection_entry (o, M_USAGE);
	      ASSERT (ace);
	      *ace = ce;
	    }
	}
      else if (o->remote_list->len == 1) /* one --remote option specified */
	{
	  connection_entry_load_re (&o->ce, o->remote_list->array[0]);
	}
      else
	{
	  ASSERT (0);
	}
    }
  if (o->connection_list)
    {
      int i;
      for (i = 0; i < o->connection_list->len; ++i)
	options_postprocess_mutate_ce (o, o->connection_list->array[i]);

#if HTTP_PROXY_OVERRIDE
      if (o->http_proxy_override)
	options_postprocess_http_proxy_override(o);
#endif
    }
  else
    options_postprocess_mutate_ce (o, &o->ce);  

#ifdef ENABLE_CRYPTOAPI
  if (o->cryptoapi_cert)
    {
      const int tls_version_max =
	  (o->ssl_flags >> SSLF_TLS_VERSION_MAX_SHIFT) &
	  SSLF_TLS_VERSION_MAX_MASK;

      if (tls_version_max == TLS_VER_UNSPEC || tls_version_max > TLS_VER_1_1)
	{
	  msg(M_WARN, "Warning: cryptapicert used, setting maximum TLS "
	      "version to 1.1.");
	  o->ssl_flags &= ~(SSLF_TLS_VERSION_MAX_MASK <<
	      SSLF_TLS_VERSION_MAX_SHIFT);
	  o->ssl_flags |= (TLS_VER_1_1 << SSLF_TLS_VERSION_MAX_SHIFT);
	}
    }
#endif /* ENABLE_CRYPTOAPI */

#if P2MP
  /*
   * Save certain parms before modifying options via --pull
   */
  pre_pull_save (o);
#endif
}

/*
 *  Check file/directory sanity
 *
 */
#ifndef ENABLE_SMALL  /** Expect people using the stripped down version to know what they do */

#define CHKACC_FILE (1<<0)       /** Check for a file/directory precense */
#define CHKACC_DIRPATH (1<<1)    /** Check for directory precense where a file should reside */
#define CHKACC_FILEXSTWR (1<<2)  /** If file exists, is it writable? */
#define CHKACC_INLINE (1<<3)     /** File is present if it's an inline file */
#define CHKACC_ACPTSTDIN (1<<4)  /** If filename is stdin, it's allowed and "exists" */

static bool
check_file_access(const int type, const char *file, const int mode, const char *opt)
{
  int errcode = 0;

  /* If no file configured, no errors to look for */
  if (!file)
      return false;

  /* If this may be an inline file, and the proper inline "filename" is set - no issues */
  if ((type & CHKACC_INLINE) && streq(file, INLINE_FILE_TAG) )
    return false;

  /* If stdin is allowed and the file name is 'stdin', then do no
   * further checks as stdin is always available
   */
  if( (type & CHKACC_ACPTSTDIN) && streq(file, "stdin") )
      return false;

  /* Is the directory path leading to the given file accessible? */
  if (type & CHKACC_DIRPATH)
    {
      char *fullpath = strdup(file);  /* POSIX dirname() implementaion may modify its arguments */
      char *dirpath = dirname(fullpath);

      if (platform_access (dirpath, mode|X_OK) != 0)
          errcode = errno;
      free(fullpath);
    }

  /* Is the file itself accessible? */
  if (!errcode && (type & CHKACC_FILE) && (platform_access (file, mode) != 0) )
      errcode = errno;

  /* If the file exists and is accessible, is it writable? */
  if (!errcode && (type & CHKACC_FILEXSTWR) && (platform_access (file, F_OK) == 0) )
    if (platform_access (file, W_OK) != 0)
      errcode = errno;

  /* Scream if an error is found */
  if( errcode > 0 )
    msg (M_NOPREFIX|M_OPTERR, "%s fails with '%s': %s",
         opt, file, strerror(errno));

  /* Return true if an error occured */
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
      return false;

  /* If chroot is set, look for the file/directory inside the chroot */
  if( chroot )
    {
      struct gc_arena gc = gc_new();
      struct buffer chroot_file;
      int len = 0;

      /* Build up a new full path including chroot directory */
      len = strlen(chroot) + strlen(PATH_SEPARATOR_STR) + strlen(file) + 1;
      chroot_file = alloc_buf_gc(len, &gc);
      buf_printf(&chroot_file, "%s%s%s", chroot, PATH_SEPARATOR_STR, file);
      ASSERT (chroot_file.len > 0);

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
  if (! command)
      return false;

  /* Extract executable path and arguments */
  argv = argv_new ();
  argv_printf (&argv, "%sc", command);

  /* if an executable is specified then check it; otherwise, complain */
  if (argv.argv[0])
    /* Scripts requires R_OK as well, but that might fail on binaries which
     * only requires X_OK to function on Unix - a scenario not unlikely to
     * be seen on suid binaries.
     */
    return_code = check_file_access_chroot(chroot, CHKACC_FILE, argv.argv[0], X_OK, opt);
  else
    {
      msg (M_NOPREFIX|M_OPTERR, "%s fails with '%s': No path to executable.",
           opt, command);
      return_code = true;
    }

  argv_reset (&argv);

  return return_code;
}

/*
 * Sanity check of all file/dir options.  Checks that file/dir
 * is accessible by OpenVPN
 */
static void
options_postprocess_filechecks (struct options *options)
{
  bool errs = false;

  /* ** SSL/TLS/crypto related files ** */
#ifdef ENABLE_SSL
  errs |= check_file_access (CHKACC_FILE|CHKACC_INLINE, options->dh_file, R_OK, "--dh");
  errs |= check_file_access (CHKACC_FILE|CHKACC_INLINE, options->ca_file, R_OK, "--ca");
  errs |= check_file_access_chroot (options->chroot_dir, CHKACC_FILE, options->ca_path, R_OK, "--capath");
  errs |= check_file_access (CHKACC_FILE|CHKACC_INLINE, options->cert_file, R_OK, "--cert");
  errs |= check_file_access (CHKACC_FILE|CHKACC_INLINE, options->extra_certs_file, R_OK,
                             "--extra-certs");
#ifdef MANAGMENT_EXTERNAL_KEY
  if(!(options->management_flags & MF_EXTERNAL_KEY))
#endif
     errs |= check_file_access (CHKACC_FILE|CHKACC_INLINE, options->priv_key_file, R_OK,
                             "--key");
  errs |= check_file_access (CHKACC_FILE|CHKACC_INLINE, options->pkcs12_file, R_OK,
                             "--pkcs12");

  if (options->ssl_flags & SSLF_CRL_VERIFY_DIR)
    errs |= check_file_access_chroot (options->chroot_dir, CHKACC_FILE, options->crl_file, R_OK|X_OK,
                               "--crl-verify directory");
  else
    errs |= check_file_access_chroot (options->chroot_dir, CHKACC_FILE, options->crl_file, R_OK,
                               "--crl-verify");

  errs |= check_file_access (CHKACC_FILE|CHKACC_INLINE, options->tls_auth_file, R_OK,
                             "--tls-auth");
#endif /* ENABLE_SSL */
#ifdef ENABLE_CRYPTO
  errs |= check_file_access (CHKACC_FILE|CHKACC_INLINE, options->shared_secret_file, R_OK,
                             "--secret");
  errs |= check_file_access (CHKACC_DIRPATH|CHKACC_FILEXSTWR,
                             options->packet_id_file, R_OK|W_OK, "--replay-persist");
#endif /* ENABLE_CRYPTO */


  /* ** Password files ** */
#ifdef ENABLE_SSL
  errs |= check_file_access (CHKACC_FILE|CHKACC_ACPTSTDIN,
			     options->key_pass_file, R_OK, "--askpass");
#endif /* ENABLE_SSL */
#ifdef ENABLE_MANAGEMENT
  errs |= check_file_access (CHKACC_FILE|CHKACC_ACPTSTDIN,
                             options->management_user_pass, R_OK,
                             "--management user/password file");
#endif /* ENABLE_MANAGEMENT */
#if P2MP
  errs |= check_file_access (CHKACC_FILE|CHKACC_ACPTSTDIN,
                             options->auth_user_pass_file, R_OK,
                             "--auth-user-pass");
#endif /* P2MP */

  /* ** System related ** */
  errs |= check_file_access (CHKACC_FILE, options->chroot_dir,
                             R_OK|X_OK, "--chroot directory");
  errs |= check_file_access (CHKACC_DIRPATH|CHKACC_FILEXSTWR, options->writepid,
                             R_OK|W_OK, "--writepid");

  /* ** Log related ** */
  errs |= check_file_access (CHKACC_DIRPATH|CHKACC_FILEXSTWR, options->status_file,
                             R_OK|W_OK, "--status");

  /* ** Config related ** */
#ifdef ENABLE_SSL
  errs |= check_file_access_chroot (options->chroot_dir, CHKACC_FILE, options->tls_export_cert,
                             R_OK|W_OK|X_OK, "--tls-export-cert");
#endif /* ENABLE_SSL */
#if P2MP_SERVER
  errs |= check_file_access_chroot (options->chroot_dir, CHKACC_FILE, options->client_config_dir,
                             R_OK|X_OK, "--client-config-dir");
  errs |= check_file_access_chroot (options->chroot_dir, CHKACC_FILE, options->tmp_dir,
                             R_OK|W_OK|X_OK, "Temporary directory (--tmp-dir)");

#endif /* P2MP_SERVER */

  if (errs)
    msg (M_USAGE, "Please correct these errors.");
}
#endif /* !ENABLE_SMALL */

/*
 * Sanity check on options.
 * Also set some options based on other
 * options.
 */
void
options_postprocess (struct options *options)
{
  options_postprocess_mutate (options);
  options_postprocess_verify (options);
#ifndef ENABLE_SMALL
  options_postprocess_filechecks (options);
#endif /* !ENABLE_SMALL */
}

#if P2MP

/*
 * Save/Restore certain option defaults before --pull is applied.
 */

void
pre_pull_save (struct options *o)
{
  if (o->pull)
    {
      ALLOC_OBJ_CLEAR_GC (o->pre_pull, struct options_pre_pull, &o->gc);
      o->pre_pull->tuntap_options = o->tuntap_options;
      o->pre_pull->tuntap_options_defined = true;
      o->pre_pull->foreign_option_index = o->foreign_option_index;
      if (o->routes)
	{
	  o->pre_pull->routes = clone_route_option_list(o->routes, &o->gc);
	  o->pre_pull->routes_defined = true;
	}
      if (o->routes_ipv6)
	{
	  o->pre_pull->routes_ipv6 = clone_route_ipv6_option_list(o->routes_ipv6, &o->gc);
	  o->pre_pull->routes_ipv6_defined = true;
	}
#ifdef ENABLE_CLIENT_NAT
      if (o->client_nat)
	{
	  o->pre_pull->client_nat = clone_client_nat_option_list(o->client_nat, &o->gc);
	  o->pre_pull->client_nat_defined = true;
	}
#endif
    }
}

void
pre_pull_restore (struct options *o)
{
  const struct options_pre_pull *pp = o->pre_pull;
  if (pp)
    {
      CLEAR (o->tuntap_options);
      if (pp->tuntap_options_defined)
	  o->tuntap_options = pp->tuntap_options;

      if (pp->routes_defined)
	{
	  rol_check_alloc (o);
	  copy_route_option_list (o->routes, pp->routes);
	}
      else
	o->routes = NULL;

      if (pp->routes_ipv6_defined)
	{
	  rol6_check_alloc (o);
	  copy_route_ipv6_option_list (o->routes_ipv6, pp->routes_ipv6);
	}
      else
	o->routes_ipv6 = NULL;

#ifdef ENABLE_CLIENT_NAT
      if (pp->client_nat_defined)
	{
	  cnol_check_alloc (o);
	  copy_client_nat_option_list (o->client_nat, pp->client_nat);
	}
      else
	o->client_nat = NULL;
#endif

      o->foreign_option_index = pp->foreign_option_index;
    }

  o->push_continuation = 0;
  o->push_option_types_found = 0;
}

#endif

#ifdef ENABLE_OCC

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
 * --fragment
 *
 * Crypto Options:
 *
 * --cipher
 * --auth
 * --keysize
 * --secret
 * --no-replay
 * --no-iv
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
options_string (const struct options *o,
		const struct frame *frame,
		struct tuntap *tt,
		bool remote,
		struct gc_arena *gc)
{
  struct buffer out = alloc_buf (OPTION_LINE_SIZE);
  bool tt_local = false;

  buf_printf (&out, "V4");

  /*
   * Tunnel Options
   */

  buf_printf (&out, ",dev-type %s", dev_type_string (o->dev, o->dev_type));
  buf_printf (&out, ",link-mtu %d", EXPANDED_SIZE (frame));
  buf_printf (&out, ",tun-mtu %d", PAYLOAD_SIZE (frame));
  buf_printf (&out, ",proto %s", proto2ascii (proto_remote (o->ce.proto, remote), true));

  /* send tun_ipv6 only in peer2peer mode - in client/server mode, it
   * is usually pushed by the server, triggering a non-helpful warning
   */
  if (o->tun_ipv6 && o->mode == MODE_POINT_TO_POINT && !PULL_DEFINED(o))
    buf_printf (&out, ",tun-ipv6");

  /*
   * Try to get ifconfig parameters into the options string.
   * If tt is undefined, make a temporary instantiation.
   */
  if (!tt)
    {
      tt = init_tun (o->dev,
		     o->dev_type,
		     o->topology,
		     o->ifconfig_local,
		     o->ifconfig_remote_netmask,
		     o->ifconfig_ipv6_local,
		     o->ifconfig_ipv6_netbits,
		     o->ifconfig_ipv6_remote,
		     (in_addr_t)0,
		     (in_addr_t)0,
		     false,
		     NULL);
      if (tt)
	tt_local = true;
    }

  if (tt && o->mode == MODE_POINT_TO_POINT && !PULL_DEFINED(o))
    {
      const char *ios = ifconfig_options_string (tt, remote, o->ifconfig_nowarn, gc);
      if (ios && strlen (ios))
	buf_printf (&out, ",ifconfig %s", ios);
    }
  if (tt_local)
    {
      free (tt);
      tt = NULL;
    }

#ifdef ENABLE_LZO
  if (o->lzo & LZO_SELECTED)
    buf_printf (&out, ",comp-lzo");
#endif

#ifdef ENABLE_FRAGMENT
  if (o->ce.fragment)
    buf_printf (&out, ",mtu-dynamic");
#endif

#ifdef ENABLE_CRYPTO

#ifdef ENABLE_SSL
#define TLS_CLIENT (o->tls_client)
#define TLS_SERVER (o->tls_server)
#else
#define TLS_CLIENT (false)
#define TLS_SERVER (false)
#endif

  /*
   * Key direction
   */
  {
    const char *kd = keydirection2ascii (o->key_direction, remote);
    if (kd)
      buf_printf (&out, ",keydir %s", kd);
  }

  /*
   * Crypto Options
   */
    if (o->shared_secret_file || TLS_CLIENT || TLS_SERVER)
      {
	struct key_type kt;

	ASSERT ((o->shared_secret_file != NULL)
		+ (TLS_CLIENT == true)
		+ (TLS_SERVER == true)
		<= 1);

	init_key_type (&kt, o->ciphername, o->ciphername_defined,
		       o->authname, o->authname_defined,
		       o->keysize, true, false);

	buf_printf (&out, ",cipher %s", cipher_kt_name (kt.cipher));
	buf_printf (&out, ",auth %s", md_kt_name (kt.digest));
	buf_printf (&out, ",keysize %d", kt.cipher_length * 8);
	if (o->shared_secret_file)
	  buf_printf (&out, ",secret");
	if (!o->replay)
	  buf_printf (&out, ",no-replay");
	if (!o->use_iv)
	  buf_printf (&out, ",no-iv");

#ifdef ENABLE_PREDICTION_RESISTANCE
        if (o->use_prediction_resistance)
          buf_printf (&out, ",use-prediction-resistance");
#endif
      }

#ifdef ENABLE_SSL
  /*
   * SSL Options
   */
  {
    if (TLS_CLIENT || TLS_SERVER)
      {
	if (o->tls_auth_file)
	  buf_printf (&out, ",tls-auth");

	if (o->key_method > 1)
	  buf_printf (&out, ",key-method %d", o->key_method);
      }

    if (remote)
      {
	if (TLS_CLIENT)
	  buf_printf (&out, ",tls-server");
	else if (TLS_SERVER)
	  buf_printf (&out, ",tls-client");
      }
    else
      {
	if (TLS_CLIENT)
	  buf_printf (&out, ",tls-client");
	else if (TLS_SERVER)
	  buf_printf (&out, ",tls-server");
      }
  }
#endif /* ENABLE_SSL */

#undef TLS_CLIENT
#undef TLS_SERVER

#endif /* ENABLE_CRYPTO */

  return BSTR (&out);
}

/*
 * Compare option strings for equality.
 * If the first two chars of the strings differ, it means that
 * we are looking at different versions of the options string,
 * therefore don't compare them and return true.
 */

bool
options_cmp_equal (char *actual, const char *expected)
{
  return options_cmp_equal_safe (actual, expected, strlen (actual) + 1);
}

void
options_warning (char *actual, const char *expected)
{
  options_warning_safe (actual, expected, strlen (actual) + 1);
}

static const char *
options_warning_extract_parm1 (const char *option_string,
			       struct gc_arena *gc_ret)
{
  struct gc_arena gc = gc_new ();
  struct buffer b = string_alloc_buf (option_string, &gc);
  char *p = gc_malloc (OPTION_PARM_SIZE, false, &gc);
  const char *ret;
  
  buf_parse (&b, ' ', p, OPTION_PARM_SIZE);
  ret = string_alloc (p, gc_ret);
  gc_free (&gc);
  return ret;
}

static void
options_warning_safe_scan2 (const int msglevel,
			    const int delim,
			    const bool report_inconsistent,
			    const char *p1,
			    const struct buffer *b2_src,
			    const char *b1_name,
			    const char *b2_name)
{
  /* we will stop sending 'proto xxx' in OCC in a future version
   * (because it's not useful), and to reduce questions when
   * interoperating, we start not-printing a warning about it today
   */
  if (strncmp(p1, "proto ", 6) == 0 )
    {
      return;
    }

  if (strlen (p1) > 0)
    {
      struct gc_arena gc = gc_new ();
      struct buffer b2 = *b2_src;
      const char *p1_prefix = options_warning_extract_parm1 (p1, &gc);
      char *p2 = gc_malloc (OPTION_PARM_SIZE, false, &gc);

      while (buf_parse (&b2, delim, p2, OPTION_PARM_SIZE))
	{
	  if (strlen (p2))
	    {
	      const char *p2_prefix = options_warning_extract_parm1 (p2, &gc);
	    
	      if (!strcmp (p1, p2))
		goto done;
	      if (!strcmp (p1_prefix, p2_prefix))
		{
		  if (report_inconsistent)
		    msg (msglevel, "WARNING: '%s' is used inconsistently, %s='%s', %s='%s'",
			 safe_print (p1_prefix, &gc),
			 b1_name,
			 safe_print (p1, &gc),
			 b2_name,
			 safe_print (p2, &gc)); 
		  goto done;
		}
	    }
	}
      
      msg (msglevel, "WARNING: '%s' is present in %s config but missing in %s config, %s='%s'",
	   safe_print (p1_prefix, &gc),
	   b1_name,
	   b2_name,
	   b1_name,	   
	   safe_print (p1, &gc));

    done:
      gc_free (&gc);
    }
}

static void
options_warning_safe_scan1 (const int msglevel,
			    const int delim,
			    const bool report_inconsistent,
			    const struct buffer *b1_src,
			    const struct buffer *b2_src,
			    const char *b1_name,
			    const char *b2_name)
{
  struct gc_arena gc = gc_new ();
  struct buffer b = *b1_src;
  char *p = gc_malloc (OPTION_PARM_SIZE, true, &gc);

  while (buf_parse (&b, delim, p, OPTION_PARM_SIZE))
      options_warning_safe_scan2 (msglevel, delim, report_inconsistent, p, b2_src, b1_name, b2_name);

  gc_free (&gc);
}

static void
options_warning_safe_ml (const int msglevel, char *actual, const char *expected, size_t actual_n)
{
  struct gc_arena gc = gc_new ();

  if (actual_n > 0)
    {
      struct buffer local = alloc_buf_gc (OPTION_PARM_SIZE + 16, &gc);
      struct buffer remote = alloc_buf_gc (OPTION_PARM_SIZE + 16, &gc);
      actual[actual_n - 1] = 0;

      buf_printf (&local, "version %s", expected);
      buf_printf (&remote, "version %s", actual);

      options_warning_safe_scan1 (msglevel, ',', true,
				  &local, &remote,
				  "local", "remote");

      options_warning_safe_scan1 (msglevel, ',', false,
				  &remote, &local,
				  "remote", "local");
    }

  gc_free (&gc);
}

bool
options_cmp_equal_safe (char *actual, const char *expected, size_t actual_n)
{
  struct gc_arena gc = gc_new ();
  bool ret = true;

  if (actual_n > 0)
    {
      actual[actual_n - 1] = 0;
#ifndef ENABLE_STRICT_OPTIONS_CHECK
      if (strncmp (actual, expected, 2))
	{
	  msg (D_SHOW_OCC, "NOTE: Options consistency check may be skewed by version differences");
	  options_warning_safe_ml (D_SHOW_OCC, actual, expected, actual_n);
	}
      else
#endif
	ret = !strcmp (actual, expected);
    }
  gc_free (&gc);
  return ret;
}

void
options_warning_safe (char *actual, const char *expected, size_t actual_n)
{
  options_warning_safe_ml (M_WARN, actual, expected, actual_n);
}

const char *
options_string_version (const char* s, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (4, gc);
  strncpynt ((char *) BPTR (&out), s, 3);
  return BSTR (&out);
}

#endif /* ENABLE_OCC */

static void
foreign_option (struct options *o, char *argv[], int len, struct env_set *es)
{
  if (len > 0)
    {
      struct gc_arena gc = gc_new();
      struct buffer name = alloc_buf_gc (OPTION_PARM_SIZE, &gc);
      struct buffer value = alloc_buf_gc (OPTION_PARM_SIZE, &gc);
      int i;
      bool first = true;
      bool good = true;

      good &= buf_printf (&name, "foreign_option_%d", o->foreign_option_index + 1);
      ++o->foreign_option_index;
      for (i = 0; i < len; ++i)
	{
	  if (argv[i])
	    {
	      if (!first)
		good &= buf_printf (&value, " ");
	      good &= buf_printf (&value, "%s", argv[i]);
	      first = false;
	    }
	}
      if (good)
	setenv_str (es, BSTR(&name), BSTR(&value));
      else
	msg (M_WARN, "foreign_option: name/value overflow");
      gc_free (&gc);
    }
}

/*
 * parse/print topology coding
 */

int
parse_topology (const char *str, const int msglevel)
{
  if (streq (str, "net30"))
    return TOP_NET30;
  else if (streq (str, "p2p"))
    return TOP_P2P;
  else if (streq (str, "subnet"))
    return TOP_SUBNET;
  else
    {
      msg (msglevel, "--topology must be net30, p2p, or subnet");
      return TOP_UNDEF;
    }
}

const char *
print_topology (const int topology)
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

#if P2MP

/*
 * Manage auth-retry variable
 */

static int global_auth_retry; /* GLOBAL */

int
auth_retry_get (void)
{
  return global_auth_retry;
}

bool
auth_retry_set (const int msglevel, const char *option)
{
  if (streq (option, "interact"))
    global_auth_retry = AR_INTERACT;
  else if (streq (option, "nointeract"))
    global_auth_retry = AR_NOINTERACT;
  else if (streq (option, "none"))
    global_auth_retry = AR_NONE;
  else
    {
      msg (msglevel, "--auth-retry method must be 'interact', 'nointeract', or 'none'");
      return false;
    }
  return true;
}

const char *
auth_retry_print (void)
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

#endif

/*
 * Print the help message.
 */
static void
usage (void)
{
  FILE *fp = msg_fp(0);

#ifdef ENABLE_SMALL

  fprintf (fp, "Usage message not available\n");

#else

  struct options o;
  init_options (&o, true);

#if defined(ENABLE_CRYPTO) && defined(ENABLE_SSL)
  fprintf (fp, usage_message,
	   title_string,
	   o.ce.connect_retry_seconds,
	   o.ce.local_port, o.ce.remote_port,
	   TUN_MTU_DEFAULT, TAP_MTU_EXTRA_DEFAULT,
	   o.verbosity,
	   o.authname, o.ciphername,
           o.replay_window, o.replay_time,
	   o.tls_timeout, o.renegotiate_seconds,
	   o.handshake_window, o.transition_window);
#elif defined(ENABLE_CRYPTO)
  fprintf (fp, usage_message,
	   title_string,
	   o.ce.connect_retry_seconds,
	   o.ce.local_port, o.ce.remote_port,
	   TUN_MTU_DEFAULT, TAP_MTU_EXTRA_DEFAULT,
	   o.verbosity,
	   o.authname, o.ciphername,
           o.replay_window, o.replay_time);
#else
  fprintf (fp, usage_message,
	   title_string,
	   o.ce.connect_retry_seconds,
	   o.ce.local_port, o.ce.remote_port,
	   TUN_MTU_DEFAULT, TAP_MTU_EXTRA_DEFAULT,
	   o.verbosity);
#endif
  fflush(fp);

#endif /* ENABLE_SMALL */
  
  openvpn_exit (OPENVPN_EXIT_STATUS_USAGE); /* exit point */
}

void
usage_small (void)
{
  msg (M_WARN|M_NOPREFIX, "Use --help for more information.");
  openvpn_exit (OPENVPN_EXIT_STATUS_USAGE); /* exit point */
}

void
show_library_versions(const unsigned int flags)
{
#ifdef ENABLE_SSL
#define SSL_LIB_VER_STR get_ssl_library_version()
#else
#define SSL_LIB_VER_STR ""
#endif
#ifdef ENABLE_LZO
#define LZO_LIB_VER_STR ", LZO ", lzo_version_string()
#else
#define LZO_LIB_VER_STR "", ""
#endif

  msg (flags, "library versions: %s%s%s", SSL_LIB_VER_STR, LZO_LIB_VER_STR);

#undef SSL_LIB_VER_STR
#undef LZO_LIB_VER_STR
}

static void
usage_version (void)
{
  msg (M_INFO|M_NOPREFIX, "%s", title_string);
  show_library_versions( M_INFO|M_NOPREFIX );
  msg (M_INFO|M_NOPREFIX, "Originally developed by James Yonan");
  msg (M_INFO|M_NOPREFIX, "Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>");
#ifndef ENABLE_SMALL
#ifdef CONFIGURE_DEFINES
  msg (M_INFO|M_NOPREFIX, "Compile time defines: %s", CONFIGURE_DEFINES);
#endif
#ifdef CONFIGURE_SPECIAL_BUILD
  msg (M_INFO|M_NOPREFIX, "special build: %s", CONFIGURE_SPECIAL_BUILD);
#endif
#ifdef CONFIGURE_GIT_REVISION
  msg (M_INFO|M_NOPREFIX, "git revision: %s", CONFIGURE_GIT_REVISION);
#endif
#endif
  openvpn_exit (OPENVPN_EXIT_STATUS_USAGE); /* exit point */
}

void
notnull (const char *arg, const char *description)
{
  if (!arg)
    msg (M_USAGE, "You must define %s", description);
}

bool
string_defined_equal (const char *s1, const char *s2)
{
  if (s1 && s2)
    return !strcmp (s1, s2);
  else
    return false;
}

#if 0
static void
ping_rec_err (int msglevel)
{
  msg (msglevel, "only one of --ping-exit or --ping-restart options may be specified");
}
#endif

static int
positive_atoi (const char *str)
{
  const int i = atoi (str);
  return i < 0 ? 0 : i;
}

#ifdef WIN32  /* This function is only used when compiling on Windows */
static unsigned int
atou (const char *str)
{
  unsigned int val = 0;
  sscanf (str, "%u", &val);
  return val;
}
#endif

static inline bool
space (unsigned char c)
{
  return c == '\0' || isspace (c);
}

int
parse_line (const char *line,
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
    error_prefix = "ERROR: ";

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
	      if (!space (in))
		{
		  if (in == ';' || in == '#') /* comment */
		    break;
		  if (!backslash && in == '\"')
		    state = STATE_READING_QUOTED_PARM;
		  else if (!backslash && in == '\'')
		    state = STATE_READING_SQUOTED_PARM;
		  else
		    {
		      out = in;
		      state = STATE_READING_UNQUOTED_PARM;
		    }
		}
	    }
	  else if (state == STATE_READING_UNQUOTED_PARM)
	    {
	      if (!backslash && space (in))
		state = STATE_DONE;
	      else
		out = in;
	    }
	  else if (state == STATE_READING_QUOTED_PARM)
	    {
	      if (!backslash && in == '\"')
		state = STATE_DONE;
	      else
		out = in;
	    }
	  else if (state == STATE_READING_SQUOTED_PARM)
	    {
	      if (in == '\'')
	        state = STATE_DONE;
	      else
	        out = in;
	    }
	  if (state == STATE_DONE)
	    {
	      /* ASSERT (parm_len > 0); */
	      p[ret] = gc_malloc (parm_len + 1, true, gc);
	      memcpy (p[ret], parm, parm_len);
	      p[ret][parm_len] = '\0';
	      state = STATE_INITIAL;
	      parm_len = 0;
	      ++ret;
	    }

	  if (backslash && out)
	    {
	      if (!(out == '\\' || out == '\"' || space (out)))
		{
#ifdef ENABLE_SMALL
		  msg (msglevel, "%sOptions warning: Bad backslash ('\\') usage in %s:%d", error_prefix, file, line_num);
#else
		  msg (msglevel, "%sOptions warning: Bad backslash ('\\') usage in %s:%d: remember that backslashes are treated as shell-escapes and if you need to pass backslash characters as part of a Windows filename, you should use double backslashes such as \"c:\\\\" PACKAGE "\\\\static.key\"", error_prefix, file, line_num);
#endif
		  return 0;
		}
	    }
	  backslash = false;
	}

      /* store parameter character */
      if (out)
	{
	  if (parm_len >= SIZE (parm))
	    {
	      parm[SIZE (parm) - 1] = 0;
	      msg (msglevel, "%sOptions error: Parameter at %s:%d is too long (%d chars max): %s",
		   error_prefix, file, line_num, (int) SIZE (parm), parm);
	      return 0;
	    }
	  parm[parm_len++] = out;
	}

      /* avoid overflow if too many parms in one config file line */
      if (ret >= n)
	break;

    } while (*c++ != '\0');

  if (state == STATE_READING_QUOTED_PARM)
    {
      msg (msglevel, "%sOptions error: No closing quotation (\") in %s:%d", error_prefix, file, line_num);
      return 0;
    }
  if (state == STATE_READING_SQUOTED_PARM)
    {
      msg (msglevel, "%sOptions error: No closing single quotation (\') in %s:%d", error_prefix, file, line_num);
      return 0;
    }
  if (state != STATE_INITIAL)
    {
      msg (msglevel, "%sOptions error: Residual parse state (%d) in %s:%d", error_prefix, state, file, line_num);
      return 0;
    }
#if 0
  {
    int i;
    for (i = 0; i < ret; ++i)
      {
	msg (M_INFO|M_NOPREFIX, "%s:%d ARG[%d] '%s'", file, line_num, i, p[i]);
      }
  }
#endif
    return ret;
}

static void
bypass_doubledash (char **p)
{
  if (strlen (*p) >= 3 && !strncmp (*p, "--", 2))
    *p += 2;
}

struct in_src {
# define IS_TYPE_FP 1
# define IS_TYPE_BUF 2
  int type;
  union {
    FILE *fp;
    struct buffer *multiline;
  } u;
};

static bool
in_src_get (const struct in_src *is, char *line, const int size)
{
  if (is->type == IS_TYPE_FP)
    {
      return BOOL_CAST (fgets (line, size, is->u.fp));
    }
  else if (is->type == IS_TYPE_BUF)
    {
      bool status = buf_parse (is->u.multiline, '\n', line, size);
      if ((int) strlen (line) + 1 < size)
	strcat (line, "\n");
      return status;
    }
  else
    {
      ASSERT (0);
      return false;
    }
}

static char *
read_inline_file (struct in_src *is, const char *close_tag, struct gc_arena *gc)
{
  char line[OPTION_LINE_SIZE];
  struct buffer buf = alloc_buf (8*OPTION_LINE_SIZE);
  char *ret;
  bool endtagfound = false;

  while (in_src_get (is, line, sizeof (line)))
    {
      if (!strncmp (line, close_tag, strlen (close_tag)))
	{
	  endtagfound = true;
	  break;
	}
      if (!buf_safe (&buf, strlen(line)+1))
	{
	  /* Increase buffer size */
	  struct buffer buf2 = alloc_buf (buf.capacity * 2);
	  ASSERT (buf_copy (&buf2, &buf));
	  buf_clear (&buf);
	  free_buf (&buf);
	  buf = buf2;
	}
      buf_printf (&buf, "%s", line);
    }
  if (!endtagfound)
    msg (M_WARN, "WARNING: Endtag %s missing", close_tag);
  ret = string_alloc (BSTR (&buf), gc);
  buf_clear (&buf);
  free_buf (&buf);
  CLEAR (line);
  return ret;
}

static bool
check_inline_file (struct in_src *is, char *p[], struct gc_arena *gc)
{
  bool ret = false;
  if (p[0] && !p[1])
    {
      char *arg = p[0];
      if (arg[0] == '<' && arg[strlen(arg)-1] == '>')
	{
	  struct buffer close_tag;
	  arg[strlen(arg)-1] = '\0';
	  p[0] = string_alloc (arg+1, gc);
	  p[1] = string_alloc (INLINE_FILE_TAG, gc);
	  close_tag = alloc_buf (strlen(p[0]) + 4);
	  buf_printf (&close_tag, "</%s>", p[0]);
	  p[2] = read_inline_file (is, BSTR (&close_tag), gc);
	  p[3] = NULL;
	  free_buf (&close_tag);
	  ret = true;
	}
    }
  return ret;
}

static bool
check_inline_file_via_fp (FILE *fp, char *p[], struct gc_arena *gc)
{
  struct in_src is;
  is.type = IS_TYPE_FP;
  is.u.fp = fp;
  return check_inline_file (&is, p, gc);
}

static bool
check_inline_file_via_buf (struct buffer *multiline, char *p[], struct gc_arena *gc)
{
  struct in_src is;
  is.type = IS_TYPE_BUF;
  is.u.multiline = multiline;
  return check_inline_file (&is, p, gc);
}

static void
add_option (struct options *options,
	    char *p[],
	    const char *file,
	    int line,
	    const int level,
	    const int msglevel,
	    const unsigned int permission_mask,
	    unsigned int *option_types_found,
	    struct env_set *es);

static void
read_config_file (struct options *options,
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
  char line[OPTION_LINE_SIZE];
  char *p[MAX_PARMS];

  ++level;
  if (level <= max_recursive_levels)
    {
      if (streq (file, "stdin"))
	fp = stdin;
      else
	fp = platform_fopen (file, "r");
      if (fp)
	{
	  line_num = 0;
	  while (fgets(line, sizeof (line), fp))
	    {
              int offset = 0;
	      CLEAR (p);
	      ++line_num;
              /* Ignore UTF-8 BOM at start of stream */
              if (line_num == 1 && strncmp (line, "\xEF\xBB\xBF", 3) == 0)
                offset = 3;
              if (parse_line (line + offset, p, SIZE (p), file, line_num, msglevel, &options->gc))
		{
		  bypass_doubledash (&p[0]);
		  check_inline_file_via_fp (fp, p, &options->gc);
		  add_option (options, p, file, line_num, level, msglevel, permission_mask, option_types_found, es);
		}
	    }
	  if (fp != stdin)
	    fclose (fp);
	}
      else
	{
	  msg (msglevel, "In %s:%d: Error opening configuration file: %s", top_file, top_line, file);
	}
    }
  else
    {
      msg (msglevel, "In %s:%d: Maximum recursive include levels exceeded in include attempt of file %s -- probably you have a configuration file that tries to include itself.", top_file, top_line, file);
    }
  CLEAR (line);
  CLEAR (p);
}

static void
read_config_string (const char *prefix,
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

  buf_set_read (&multiline, (uint8_t*)config, strlen (config));

  while (buf_parse (&multiline, '\n', line, sizeof (line)))
    {
      char *p[MAX_PARMS];
      CLEAR (p);
      ++line_num;
      if (parse_line (line, p, SIZE (p), prefix, line_num, msglevel, &options->gc))
	{
	  bypass_doubledash (&p[0]);
	  check_inline_file_via_buf (&multiline, p, &options->gc);
	  add_option (options, p, prefix, line_num, 0, msglevel, permission_mask, option_types_found, es);
	}
      CLEAR (p);
    }
  CLEAR (line);
}

void
parse_argv (struct options *options,
	    const int argc,
	    char *argv[],
	    const int msglevel,
	    const unsigned int permission_mask,
	    unsigned int *option_types_found,
	    struct env_set *es)
{
  int i, j;

  /* usage message */
  if (argc <= 1)
    usage ();

  /* config filename specified only? */
  if (argc == 2 && strncmp (argv[1], "--", 2))
    {
      char *p[MAX_PARMS];
      CLEAR (p);
      p[0] = "config";
      p[1] = argv[1];
      add_option (options, p, NULL, 0, 0, msglevel, permission_mask, option_types_found, es);
    }
  else
    {
      /* parse command line */
      for (i = 1; i < argc; ++i)
	{
	  char *p[MAX_PARMS];
	  CLEAR (p);
	  p[0] = argv[i];
	  if (strncmp(p[0], "--", 2))
	    {
	      msg (msglevel, "I'm trying to parse \"%s\" as an --option parameter but I don't see a leading '--'", p[0]);
	    }
	  else
	    p[0] += 2;

	  for (j = 1; j < MAX_PARMS; ++j)
	    {
	      if (i + j < argc)
		{
		  char *arg = argv[i + j];
		  if (strncmp (arg, "--", 2))
		    p[j] = arg;
		  else
		    break;
		}
	    }
	  add_option (options, p, NULL, 0, 0, msglevel, permission_mask, option_types_found, es);
	  i += j - 1;
	}
    }
}

bool
apply_push_options (struct options *options,
		    struct buffer *buf,
		    unsigned int permission_mask,
		    unsigned int *option_types_found,
		    struct env_set *es)
{
  char line[OPTION_PARM_SIZE];
  int line_num = 0;
  const char *file = "[PUSH-OPTIONS]";
  const int msglevel = D_PUSH_ERRORS|M_OPTERR;

  while (buf_parse (buf, ',', line, sizeof (line)))
    {
      char *p[MAX_PARMS];
      CLEAR (p);
      ++line_num;
      if (parse_line (line, p, SIZE (p), file, line_num, msglevel, &options->gc))
	{
	  add_option (options, p, file, line_num, 0, msglevel, permission_mask, option_types_found, es);
	}
    }
  return true;
}

void
options_server_import (struct options *o,
		       const char *filename,
		       int msglevel,
		       unsigned int permission_mask,
		       unsigned int *option_types_found,
		       struct env_set *es)
{
  msg (D_PUSH, "OPTIONS IMPORT: reading client specific options from: %s", filename);
  read_config_file (o,
		    filename,
		    0,
		    filename,
		    0,
		    msglevel,
		    permission_mask,
		    option_types_found,
		    es);
}

void options_string_import (struct options *options,
			    const char *config,
			    const int msglevel,
			    const unsigned int permission_mask,
			    unsigned int *option_types_found,
			    struct env_set *es)
{
  read_config_string ("[CONFIG-STRING]", options, config, msglevel, permission_mask, option_types_found, es);
}

#if P2MP

#define VERIFY_PERMISSION(mask) { if (!verify_permission(p[0], file, line, (mask), permission_mask, option_types_found, msglevel, options)) goto err; }

static bool
verify_permission (const char *name,
		   const char* file,
		   int line,
		   const unsigned int type,
		   const unsigned int allowed,
		   unsigned int *found,
		   const int msglevel,
		   struct options* options)
{
  if (!(type & allowed))
    {
      msg (msglevel, "option '%s' cannot be used in this context (%s)", name, file);
      return false;
    }

  if (found)
    *found |= type;

#ifndef ENABLE_SMALL
  /* Check if this options is allowed in connection block,
   * but we are currently not in a connection block
   * Parsing a connection block uses a temporary options struct without
   * connection_list
   */

  if ((type & OPT_P_CONNECTION) && options->connection_list)
    {
      if (file)
	msg (M_WARN, "Option '%s' in %s:%d is ignored by previous <connection> blocks ", name, file, line);
      else
	msg (M_WARN, "Option '%s' is ignored by previous <connection> blocks", name);
    }
#endif
  return true;
}

#else

#define VERIFY_PERMISSION(mask)

#endif

/*
 * Check that an option doesn't have too
 * many parameters.
 */

#define NM_QUOTE_HINT (1<<0)

static bool
no_more_than_n_args (const int msglevel,
		     char *p[],
		     const int max,
		     const unsigned int flags)
{
  const int len = string_array_len ((const char **)p);

  if (!len)
    return false;

  if (len > max)
    {
      msg (msglevel, "the --%s directive should have at most %d parameter%s.%s",
	   p[0],
	   max - 1,
	   max >= 3 ? "s" : "",
	   (flags & NM_QUOTE_HINT) ? "  To pass a list of arguments as one of the parameters, try enclosing them in double quotes (\"\")." : "");
      return false;
    }
  else
    return true;
}

static inline int
msglevel_forward_compatible (struct options *options, const int msglevel)
{
  return options->forward_compatible ? M_WARN : msglevel;
}

static void
set_user_script (struct options *options,
		 const char **script,
		 const char *new_script,
		 const char *type,
		 bool in_chroot)
{
  if (*script) {
    msg (M_WARN, "Multiple --%s scripts defined.  "
	 "The previously configured script is overridden.", type);
  }
  *script = new_script;
  options->user_script_used = true;

#ifndef ENABLE_SMALL
  {
    char script_name[100];
    openvpn_snprintf (script_name, sizeof(script_name),
                      "--%s script", type);

    if (check_cmd_access (*script, script_name, (in_chroot ? options->chroot_dir : NULL)))
      msg (M_USAGE, "Please correct this error.");

  }
#endif
}


static void
add_option (struct options *options,
	    char *p[],
	    const char *file,
	    int line,
	    const int level,
	    const int msglevel,
	    const unsigned int permission_mask,
	    unsigned int *option_types_found,
	    struct env_set *es)
{
  struct gc_arena gc = gc_new ();
  const bool pull_mode = BOOL_CAST (permission_mask & OPT_P_PULL_MODE);
  int msglevel_fc = msglevel_forward_compatible (options, msglevel);

  ASSERT (MAX_PARMS >= 7);

  /*
   * If directive begins with "setenv opt" prefix, don't raise an error if
   * directive is unrecognized.
   */
  if (streq (p[0], "setenv") && p[1] && streq (p[1], "opt") && !(permission_mask & OPT_P_PULL_MODE))
    {
      p += 2;
      msglevel_fc = M_WARN;
    }

  if (!file)
    {
      file = "[CMD-LINE]";
      line = 1;
    }
  if (streq (p[0], "help"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      usage ();
    }
  if (streq (p[0], "version"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      usage_version ();
    }
  else if (streq (p[0], "config") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_CONFIG);

      /* save first config file only in options */
      if (!options->config)
	options->config = p[1];

      read_config_file (options, p[1], level, file, line, msglevel, permission_mask, option_types_found, es);
    }
#if defined(ENABLE_DEBUG) && !defined(ENABLE_SMALL)
  else if (streq (p[0], "show-gateway"))
    {
      struct route_gateway_info rgi;
      VERIFY_PERMISSION (OPT_P_GENERAL);
      get_default_gateway(&rgi);
      print_default_gateway(M_INFO, &rgi);
      openvpn_exit (OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }
#endif
#if 0
  else if (streq (p[0], "foreign-option") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_IPWIN32);
      foreign_option (options, p, 3, es);
    }
#endif
  else if (streq (p[0], "echo") || streq (p[0], "parameter"))
    {
      struct buffer string = alloc_buf_gc (OPTION_PARM_SIZE, &gc);
      int j;
      bool good = true;

      VERIFY_PERMISSION (OPT_P_ECHO);

      for (j = 1; j < MAX_PARMS; ++j)
	{
	  if (!p[j])
	    break;
	  if (j > 1)
	    good &= buf_printf (&string, " ");
	  good &= buf_printf (&string, "%s", p[j]);
	}
      if (good)
	{
#if 0
	  /* removed for now since ECHO can potentially include
	     security-sensitive strings */
	  msg (M_INFO, "%s:%s",
	       pull_mode ? "ECHO-PULL" : "ECHO",
	       BSTR (&string));
#endif
#ifdef ENABLE_MANAGEMENT
	  if (management)
	    management_echo (management, BSTR (&string), pull_mode);
#endif
	}
      else
	msg (M_WARN, "echo/parameter option overflow");
    }
#ifdef ENABLE_MANAGEMENT
  else if (streq (p[0], "management") && p[1] && p[2])
    {
      int port = 0;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (streq (p[2], "unix"))
	{
#if UNIX_SOCK_SUPPORT
	  options->management_flags |= MF_UNIX_SOCK;
#else
	  msg (msglevel, "MANAGEMENT: this platform does not support unix domain sockets");
	  goto err;
#endif
	}
      else
	{
	  port = atoi (p[2]);
	  if (!legal_ipv4_port (port))
	    {
	      msg (msglevel, "port number associated with --management directive is out of range");
	      goto err;
	    }
	}

      options->management_addr = p[1];
      options->management_port = port;
      if (p[3])
	{
	  options->management_user_pass = p[3];
	}
    }
  else if (streq (p[0], "management-client-user") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->management_client_user = p[1];
    }
  else if (streq (p[0], "management-client-group") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->management_client_group = p[1];
    }
  else if (streq (p[0], "management-query-passwords"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->management_flags |= MF_QUERY_PASSWORDS;
    }
  else if (streq (p[0], "management-query-remote"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->management_flags |= MF_QUERY_REMOTE;
    }
  else if (streq (p[0], "management-query-proxy"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->management_flags |= MF_QUERY_PROXY;
      options->force_connection_list = true;
    }
  else if (streq (p[0], "management-hold"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->management_flags |= MF_HOLD;
    }
  else if (streq (p[0], "management-signal"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->management_flags |= MF_SIGNAL;
    }
  else if (streq (p[0], "management-forget-disconnect"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->management_flags |= MF_FORGET_DISCONNECT;
    }
  else if (streq (p[0], "management-up-down"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->management_flags |= MF_UP_DOWN;
    }
  else if (streq (p[0], "management-client"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->management_flags |= MF_CONNECT_AS_CLIENT;
      options->management_write_peer_info_file = p[1];
    }
#ifdef MANAGMENT_EXTERNAL_KEY
  else if (streq (p[0], "management-external-key"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->management_flags |= MF_EXTERNAL_KEY;
    }
#endif
#ifdef MANAGEMENT_DEF_AUTH
  else if (streq (p[0], "management-client-auth"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->management_flags |= MF_CLIENT_AUTH;
    }
#endif
#ifdef ENABLE_X509_TRACK
  else if (streq (p[0], "x509-track") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      x509_track_add (&options->x509_track, p[1], msglevel, &options->gc);
    }
#endif
#ifdef MANAGEMENT_PF
  else if (streq (p[0], "management-client-pf"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->management_flags |= (MF_CLIENT_PF | MF_CLIENT_AUTH);
    }
#endif
  else if (streq (p[0], "management-log-cache") && p[1])
    {
      int cache;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      cache = atoi (p[1]);
      if (cache < 1)
	{
	  msg (msglevel, "--management-log-cache parameter is out of range");
	  goto err;
	}
      options->management_log_history_cache = cache;
    }
#endif
#ifdef ENABLE_PLUGIN
  else if (streq (p[0], "plugin") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_PLUGIN);
      if (!options->plugin_list)
	options->plugin_list = plugin_option_list_new (&options->gc);
      if (!plugin_option_list_add (options->plugin_list, &p[1], &options->gc))
	{
	  msg (msglevel, "plugin add failed: %s", p[1]);
	  goto err;
	}
    }
#endif
  else if (streq (p[0], "mode") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (streq (p[1], "p2p"))
	options->mode = MODE_POINT_TO_POINT;
#if P2MP_SERVER
      else if (streq (p[1], "server"))
	options->mode = MODE_SERVER;
#endif
      else
	{
	  msg (msglevel, "Bad --mode parameter: %s", p[1]);
	  goto err;
	}
    }
  else if (streq (p[0], "dev") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->dev = p[1];
    }
  else if (streq (p[0], "dev-type") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->dev_type = p[1];
    }
  else if (streq (p[0], "dev-node") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->dev_node = p[1];
    }
  else if (streq (p[0], "lladdr") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_UP);
      if (mac_addr_safe (p[1])) /* MAC address only */
	options->lladdr = p[1];
      else
	{
	  msg (msglevel, "lladdr parm '%s' must be a MAC address", p[1]);
	  goto err;
	}
    }
  else if (streq (p[0], "topology") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_UP);
      options->topology = parse_topology (p[1], msglevel);
    }
  else if (streq (p[0], "tun-ipv6"))
    {
      VERIFY_PERMISSION (OPT_P_UP);
      options->tun_ipv6 = true;
    }
#ifdef ENABLE_IPROUTE
  else if (streq (p[0], "iproute") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      iproute_path = p[1];
    }
#endif
  else if (streq (p[0], "ifconfig") && p[1] && p[2])
    {
      VERIFY_PERMISSION (OPT_P_UP);
      if (ip_or_dns_addr_safe (p[1], options->allow_pull_fqdn) && ip_or_dns_addr_safe (p[2], options->allow_pull_fqdn)) /* FQDN -- may be DNS name */
	{
	  options->ifconfig_local = p[1];
	  options->ifconfig_remote_netmask = p[2];
	}
      else
	{
	  msg (msglevel, "ifconfig parms '%s' and '%s' must be valid addresses", p[1], p[2]);
	  goto err;
	}
    }
  else if (streq (p[0], "ifconfig-ipv6") && p[1] && p[2] )
    {
      unsigned int netbits;
      char * ipv6_local;

      VERIFY_PERMISSION (OPT_P_UP);
      if ( get_ipv6_addr( p[1], NULL, &netbits, &ipv6_local, msglevel ) &&
           ipv6_addr_safe( p[2] ) )
        {
	  if ( netbits < 64 || netbits > 124 )
	    {
	      msg( msglevel, "ifconfig-ipv6: /netbits must be between 64 and 124, not '/%d'", netbits );
	      goto err;
	    }

          if (options->ifconfig_ipv6_local)
            /* explicitly ignoring this is a const char */
            free ((char *) options->ifconfig_ipv6_local);

	  options->ifconfig_ipv6_local = ipv6_local;
	  options->ifconfig_ipv6_netbits = netbits;
	  options->ifconfig_ipv6_remote = p[2];
        }
      else
	{
	  msg (msglevel, "ifconfig-ipv6 parms '%s' and '%s' must be valid addresses", p[1], p[2]);
	  goto err;
	}
    }
  else if (streq (p[0], "ifconfig-noexec"))
    {
      VERIFY_PERMISSION (OPT_P_UP);
      options->ifconfig_noexec = true;
    }
  else if (streq (p[0], "ifconfig-nowarn"))
    {
      VERIFY_PERMISSION (OPT_P_UP);
      options->ifconfig_nowarn = true;
    }
  else if (streq (p[0], "local") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      options->ce.local = p[1];
    }
  else if (streq (p[0], "remote-random"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->remote_random = true;
    }
  else if (streq (p[0], "connection") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (streq (p[1], INLINE_FILE_TAG) && p[2])
	{
	  struct options sub;
	  struct connection_entry *e;

	  init_options (&sub, true);
	  sub.ce = options->ce;
	  read_config_string ("[CONNECTION-OPTIONS]", &sub, p[2], msglevel, OPT_P_CONNECTION, option_types_found, es);
	  if (!sub.ce.remote)
	    {
	      msg (msglevel, "Each 'connection' block must contain exactly one 'remote' directive");
	      goto err;
	    }

	  e = alloc_connection_entry (options, msglevel);
	  if (!e)
	    goto err;
	  *e = sub.ce;
	  gc_transfer (&options->gc, &sub.gc);
	  uninit_options (&sub);
	}
    }
  else if (streq (p[0], "ignore-unknown-option") && p[1])
    {
      int i;
      int j;
      int numignored=0;
      const char **ignore;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      /* Find out how many options to be ignored */
      for (i=1;p[i];i++)
        numignored++;

      /* add number of options already ignored */
      for (i=0;options->ignore_unknown_option &&
             options->ignore_unknown_option[i]; i++)
        numignored++;

      /* Allocate array */
      ALLOC_ARRAY_GC (ignore, const char*, numignored+1, &options->gc);
      for (i=0;options->ignore_unknown_option &&
             options->ignore_unknown_option[i]; i++)
        ignore[i]=options->ignore_unknown_option[i];

      options->ignore_unknown_option=ignore;

      for (j=1;p[j];j++)
        {
          /* Allow the user to specify ignore-unknown-option --opt too */
          if (p[j][0]=='-' && p[j][1]=='-')
            options->ignore_unknown_option[i] = (p[j]+2);
          else
            options->ignore_unknown_option[i] = p[j];
          i++;
        }

      options->ignore_unknown_option[i] = NULL;
    }
  else if (streq (p[0], "remote-ip-hint") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->remote_ip_hint = p[1];
    }
#if HTTP_PROXY_OVERRIDE
  else if (streq (p[0], "http-proxy-override") && p[1] && p[2])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->http_proxy_override = parse_http_proxy_override(p[1], p[2], p[3], msglevel, &options->gc);
      if (!options->http_proxy_override)
	goto err;
      options->force_connection_list = true;
    }
#endif
  else if (streq (p[0], "remote") && p[1])
    {
      struct remote_entry re;
      re.remote = NULL;
      re.remote_port = re.proto = -1;

      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      re.remote = p[1];
      if (p[2])
	{
	  const int port = atoi (p[2]);
	  if (!legal_ipv4_port (port))
	    {
	      msg (msglevel, "remote: port number associated with host %s is out of range", p[1]);
	      goto err;
	    }
	  re.remote_port = port;
	  if (p[3])
	    {
	      const int proto = ascii2proto (p[3]);
	      if (proto < 0)
		{
		  msg (msglevel, "remote: bad protocol associated with host %s: '%s'", p[1], p[3]);
		  goto err;
		}
	      re.proto = proto;
	    }
	}
      if (permission_mask & OPT_P_GENERAL)
	{
	  struct remote_entry *e = alloc_remote_entry (options, msglevel);
	  if (!e)
	    goto err;
	  *e = re;
	}
      else if (permission_mask & OPT_P_CONNECTION)
	{
	  connection_entry_load_re (&options->ce, &re);
	}
    }
  else if (streq (p[0], "resolv-retry") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (streq (p[1], "infinite"))
	options->resolve_retry_seconds = RESOLV_RETRY_INFINITE;
      else
	options->resolve_retry_seconds = positive_atoi (p[1]);
    }
  else if (streq (p[0], "connect-retry") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      options->ce.connect_retry_seconds = positive_atoi (p[1]);
      options->ce.connect_retry_defined = true;
    }
  else if (streq (p[0], "connect-timeout") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      options->ce.connect_timeout = positive_atoi (p[1]);
      options->ce.connect_timeout_defined = true;
    }
  else if (streq (p[0], "connect-retry-max") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      options->ce.connect_retry_max = positive_atoi (p[1]);
    }
  else if (streq (p[0], "ipchange") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_SCRIPT);
      if (!no_more_than_n_args (msglevel, p, 2, NM_QUOTE_HINT))
	goto err;
      set_user_script (options,
		       &options->ipchange,
		       string_substitute (p[1], ',', ' ', &options->gc),
		       "ipchange", true);
    }
  else if (streq (p[0], "float"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      options->ce.remote_float = true;
    }
#ifdef ENABLE_DEBUG
  else if (streq (p[0], "gremlin") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->gremlin = positive_atoi (p[1]);
    }
#endif
  else if (streq (p[0], "chroot") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->chroot_dir = p[1];
    }
  else if (streq (p[0], "cd") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (platform_chdir (p[1]))
	{
	  msg (M_ERR, "cd to '%s' failed", p[1]);
	  goto err;
	}
      options->cd_dir = p[1];
    }
#ifdef ENABLE_SELINUX
  else if (streq (p[0], "setcon") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->selinux_context = p[1];
    }
#endif
  else if (streq (p[0], "writepid") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->writepid = p[1];
    }
  else if (streq (p[0], "up") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_SCRIPT);
      if (!no_more_than_n_args (msglevel, p, 2, NM_QUOTE_HINT))
	goto err;
      set_user_script (options, &options->up_script, p[1], "up", false);
    }
  else if (streq (p[0], "down") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_SCRIPT);
      if (!no_more_than_n_args (msglevel, p, 2, NM_QUOTE_HINT))
	goto err;
      set_user_script (options, &options->down_script, p[1], "down", true);
    }
  else if (streq (p[0], "down-pre"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->down_pre = true;
    }
  else if (streq (p[0], "up-delay"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->up_delay = true;
    }
  else if (streq (p[0], "up-restart"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->up_restart = true;
    }
  else if (streq (p[0], "syslog"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      open_syslog (p[1], false);
    }
  else if (streq (p[0], "daemon"))
    {
      bool didit = false;
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (!options->daemon)
	{
	  options->daemon = didit = true;
	  open_syslog (p[1], false);
	}
      if (p[1])
	{
	  if (!didit)
	    {
	      msg (M_WARN, "WARNING: Multiple --daemon directives specified, ignoring --daemon %s. (Note that initscripts sometimes add their own --daemon directive.)", p[1]);
	      goto err;
	    }
	}
    }
  else if (streq (p[0], "inetd"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (!options->inetd)
	{
	  int z;
	  const char *name = NULL;
	  const char *opterr = "when --inetd is used with two parameters, one of them must be 'wait' or 'nowait' and the other must be a daemon name to use for system logging";

	  options->inetd = -1;

	  for (z = 1; z <= 2; ++z)
	    {
	      if (p[z])
		{
		  if (streq (p[z], "wait"))
		    {
		      if (options->inetd != -1)
			{
			  msg (msglevel, "%s", opterr);
			  goto err;
			}
		      else
			options->inetd = INETD_WAIT;
		    }
		  else if (streq (p[z], "nowait"))
		    {
		      if (options->inetd != -1)
			{
			  msg (msglevel, "%s", opterr);
			  goto err;
			}
		      else
			options->inetd = INETD_NOWAIT;
		    }
		  else
		    {
		      if (name != NULL)
			{
			  msg (msglevel, "%s", opterr);
			  goto err;
			}
		      name = p[z];
		    }
		}
	    }

	  /* default */
	  if (options->inetd == -1)
	    options->inetd = INETD_WAIT;

	  save_inetd_socket_descriptor ();
	  open_syslog (name, true);
	}
    }
  else if (streq (p[0], "log") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->log = true;
      redirect_stdout_stderr (p[1], false);
    }
  else if (streq (p[0], "suppress-timestamps"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->suppress_timestamps = true;
      set_suppress_timestamps(true);
    }
  else if (streq (p[0], "log-append") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->log = true;
      redirect_stdout_stderr (p[1], true);
    }
#ifdef ENABLE_MEMSTATS
  else if (streq (p[0], "memstats") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->memstats_fn = p[1];
    }
#endif
  else if (streq (p[0], "mlock"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->mlock = true;
    }
#if ENABLE_IP_PKTINFO
  else if (streq (p[0], "multihome"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->sockflags |= SF_USE_IP_PKTINFO;
    }
#endif
  else if (streq (p[0], "verb") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_MESSAGES);
      options->verbosity = positive_atoi (p[1]);
#if !defined(ENABLE_DEBUG) && !defined(ENABLE_SMALL)
      /* Warn when a debug verbosity is supplied when built without debug support */
      if (options->verbosity >= 7)
        msg (M_WARN, "NOTE: debug verbosity (--verb %d) is enabled but this build lacks debug support.",
	    options->verbosity);
#endif
    }
  else if (streq (p[0], "mute") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_MESSAGES);
      options->mute = positive_atoi (p[1]);
    }
  else if (streq (p[0], "errors-to-stderr"))
    {
      VERIFY_PERMISSION (OPT_P_MESSAGES);
      errors_to_stderr();
    }
  else if (streq (p[0], "status") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->status_file = p[1];
      if (p[2])
	{
	  options->status_file_update_freq = positive_atoi (p[2]);
	}
    }
  else if (streq (p[0], "status-version") && p[1])
    {
      int version;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      version = atoi (p[1]);
      if (version < 1 || version > 3)
	{
	  msg (msglevel, "--status-version must be 1 to 3");
	  goto err;
	}
      options->status_file_version = version;
    }
  else if (streq (p[0], "remap-usr1") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (streq (p[1], "SIGHUP"))
	options->remap_sigusr1 = SIGHUP;
      else if (streq (p[1], "SIGTERM"))
	options->remap_sigusr1 = SIGTERM;
      else
	{
	  msg (msglevel, "--remap-usr1 parm must be 'SIGHUP' or 'SIGTERM'");
	  goto err;
	}
    }
  else if ((streq (p[0], "link-mtu") || streq (p[0], "udp-mtu")) && p[1])
    {
      VERIFY_PERMISSION (OPT_P_MTU|OPT_P_CONNECTION);
      options->ce.link_mtu = positive_atoi (p[1]);
      options->ce.link_mtu_defined = true;
    }
  else if (streq (p[0], "tun-mtu") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_MTU|OPT_P_CONNECTION);
      options->ce.tun_mtu = positive_atoi (p[1]);
      options->ce.tun_mtu_defined = true;
    }
  else if (streq (p[0], "tun-mtu-extra") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_MTU|OPT_P_CONNECTION);
      options->ce.tun_mtu_extra = positive_atoi (p[1]);
      options->ce.tun_mtu_extra_defined = true;
    }
#ifdef ENABLE_FRAGMENT
  else if (streq (p[0], "mtu-dynamic"))
    {
      VERIFY_PERMISSION (OPT_P_MTU|OPT_P_CONNECTION);
      msg (msglevel, "--mtu-dynamic has been replaced by --fragment");
      goto err;
    }
  else if (streq (p[0], "fragment") && p[1])
    {
/*      VERIFY_PERMISSION (OPT_P_MTU); */
      VERIFY_PERMISSION (OPT_P_MTU|OPT_P_CONNECTION);
      options->ce.fragment = positive_atoi (p[1]);
    }
#endif
  else if (streq (p[0], "mtu-disc") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_MTU|OPT_P_CONNECTION);
      options->ce.mtu_discover_type = translate_mtu_discover_type_name (p[1]);
    }
#ifdef ENABLE_OCC
  else if (streq (p[0], "mtu-test"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->mtu_test = true;
    }
#endif
  else if (streq (p[0], "nice") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_NICE);
      options->nice = atoi (p[1]);
    }
  else if (streq (p[0], "rcvbuf") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_SOCKBUF);
      options->rcvbuf = positive_atoi (p[1]);
    }
  else if (streq (p[0], "sndbuf") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_SOCKBUF);
      options->sndbuf = positive_atoi (p[1]);
    }
  else if (streq (p[0], "mark") && p[1])
    {
#if defined(TARGET_LINUX) && HAVE_DECL_SO_MARK
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->mark = atoi(p[1]);
#endif
    }
  else if (streq (p[0], "socket-flags"))
    {
      int j;
      VERIFY_PERMISSION (OPT_P_SOCKFLAGS);
      for (j = 1; j < MAX_PARMS && p[j]; ++j)
	{
	  if (streq (p[j], "TCP_NODELAY"))
	    options->sockflags |= SF_TCP_NODELAY;
	  else
	    msg (msglevel, "unknown socket flag: %s", p[j]);	    
	}
    }
  else if (streq (p[0], "txqueuelen") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
#ifdef TARGET_LINUX
      options->tuntap_options.txqueuelen = positive_atoi (p[1]);
#else
      msg (msglevel, "--txqueuelen not supported on this OS");
      goto err;
#endif
    }
  else if (streq (p[0], "shaper") && p[1])
    {
#ifdef ENABLE_FEATURE_SHAPER
      int shaper;

      VERIFY_PERMISSION (OPT_P_SHAPER);
      shaper = atoi (p[1]);
      if (shaper < SHAPER_MIN || shaper > SHAPER_MAX)
	{
	  msg (msglevel, "Bad shaper value, must be between %d and %d",
	       SHAPER_MIN, SHAPER_MAX);
	  goto err;
	}
      options->shaper = shaper;
#else /* ENABLE_FEATURE_SHAPER */
      VERIFY_PERMISSION (OPT_P_GENERAL);
      msg (msglevel, "--shaper requires the gettimeofday() function which is missing");
      goto err;
#endif /* ENABLE_FEATURE_SHAPER */
    }
  else if (streq (p[0], "port") && p[1])
    {
      int port;

      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      port = atoi (p[1]);
      if (!legal_ipv4_port (port))
	{
	  msg (msglevel, "Bad port number: %s", p[1]);
	  goto err;
	}
      options->ce.local_port = options->ce.remote_port = port;
    }
  else if (streq (p[0], "lport") && p[1])
    {
      int port;

      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      port = atoi (p[1]);
      if ((port != 0) && !legal_ipv4_port (port))
	{
	  msg (msglevel, "Bad local port number: %s", p[1]);
	  goto err;
	}
      options->ce.local_port_defined = true;
      options->ce.local_port = port;
    }
  else if (streq (p[0], "rport") && p[1])
    {
      int port;

      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      port = atoi (p[1]);
      if (!legal_ipv4_port (port))
	{
	  msg (msglevel, "Bad remote port number: %s", p[1]);
	  goto err;
	}
      options->ce.remote_port = port;
    }
  else if (streq (p[0], "bind"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      options->ce.bind_defined = true;
    }
  else if (streq (p[0], "nobind"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      options->ce.bind_local = false;
    }
  else if (streq (p[0], "fast-io"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->fast_io = true;
    }
  else if (streq (p[0], "inactive") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_TIMER);
      options->inactivity_timeout = positive_atoi (p[1]);
      if (p[2])
	options->inactivity_minimum_bytes = positive_atoi (p[2]);
    }
  else if (streq (p[0], "proto") && p[1])
    {
      int proto;
      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      proto = ascii2proto (p[1]);
      if (proto < 0)
	{
	  msg (msglevel, "Bad protocol: '%s'.  Allowed protocols with --proto option: %s",
	       p[1],
	       proto2ascii_all (&gc));
	  goto err;
	}
      options->ce.proto = proto;
    }
  else if (streq (p[0], "proto-force") && p[1])
    {
      int proto_force;
      VERIFY_PERMISSION (OPT_P_GENERAL);
      proto_force = ascii2proto (p[1]);
      if (proto_force < 0)
	{
	  msg (msglevel, "Bad --proto-force protocol: '%s'", p[1]);
	  goto err;
	}
      options->proto_force = proto_force;
      options->force_connection_list = true;
    }
#ifdef ENABLE_HTTP_PROXY
  else if (streq (p[0], "http-proxy") && p[1])
    {
      struct http_proxy_options *ho;

      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);

      {
	int port;
	if (!p[2])
	  {
	    msg (msglevel, "http-proxy port number not defined");
	    goto err;
	  }
	port = atoi (p[2]);
	if (!legal_ipv4_port (port))
	  {
	    msg (msglevel, "Bad http-proxy port number: %s", p[2]);
	    goto err;
	  }
	
	ho = init_http_proxy_options_once (&options->ce.http_proxy_options, &options->gc);
	
	ho->server = p[1];
	ho->port = port;
      }

      if (p[3])
	{
	  /* auto -- try to figure out proxy addr, port, and type automatically */
	  /* semiauto -- given proxy addr:port, try to figure out type automatically */
	  /* (auto|semiauto)-nct -- disable proxy auth cleartext protocols (i.e. basic auth) */
	  if (streq (p[3], "auto"))
	    ho->auth_retry = PAR_ALL;
	  else if (streq (p[3], "auto-nct"))
	    ho->auth_retry = PAR_NCT;
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
  else if (streq (p[0], "http-proxy-retry"))
    {
      struct http_proxy_options *ho;
      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      ho = init_http_proxy_options_once (&options->ce.http_proxy_options, &options->gc);
      ho->retry = true;
    }
  else if (streq (p[0], "http-proxy-timeout") && p[1])
    {
      struct http_proxy_options *ho;

      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      ho = init_http_proxy_options_once (&options->ce.http_proxy_options, &options->gc);
      ho->timeout = positive_atoi (p[1]);
    }
  else if (streq (p[0], "http-proxy-option") && p[1])
    {
      struct http_proxy_options *ho;

      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      ho = init_http_proxy_options_once (&options->ce.http_proxy_options, &options->gc);

      if (streq (p[1], "VERSION") && p[2])
	{
	  ho->http_version = p[2];
	}
      else if (streq (p[1], "AGENT") && p[2])
	{
	  ho->user_agent = p[2];
	}
      else
	{
	  msg (msglevel, "Bad http-proxy-option or missing parameter: '%s'", p[1]);
	}
    }
#endif
#ifdef ENABLE_SOCKS
  else if (streq (p[0], "socks-proxy") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);

      if (p[2])
	{
	  int port;
          port = atoi (p[2]);
          if (!legal_ipv4_port (port))
	    {
	      msg (msglevel, "Bad socks-proxy port number: %s", p[2]);
	      goto err;
	    }
          options->ce.socks_proxy_port = port;
	}
      else
	{
	  options->ce.socks_proxy_port = 1080;
	}
      options->ce.socks_proxy_server = p[1];
      options->ce.socks_proxy_authfile = p[3]; /* might be NULL */
    }
  else if (streq (p[0], "socks-proxy-retry"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      options->ce.socks_proxy_retry = true;
    }
#endif
  else if (streq (p[0], "keepalive") && p[1] && p[2])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->keepalive_ping = atoi (p[1]);
      options->keepalive_timeout = atoi (p[2]);
    }
  else if (streq (p[0], "ping") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_TIMER);
      options->ping_send_timeout = positive_atoi (p[1]);
    }
  else if (streq (p[0], "ping-exit") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_TIMER);
      options->ping_rec_timeout = positive_atoi (p[1]);
      options->ping_rec_timeout_action = PING_EXIT;
    }
  else if (streq (p[0], "ping-restart") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_TIMER);
      options->ping_rec_timeout = positive_atoi (p[1]);
      options->ping_rec_timeout_action = PING_RESTART;
    }
  else if (streq (p[0], "ping-timer-rem"))
    {
      VERIFY_PERMISSION (OPT_P_TIMER);
      options->ping_timer_remote = true;
    }
#ifdef ENABLE_OCC
  else if (streq (p[0], "explicit-exit-notify"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION|OPT_P_EXPLICIT_NOTIFY);
      if (p[1])
	{
	  options->ce.explicit_exit_notification = positive_atoi (p[1]);
	}
      else
	{
	  options->ce.explicit_exit_notification = 1;
	}
    }
#endif
  else if (streq (p[0], "persist-tun"))
    {
      VERIFY_PERMISSION (OPT_P_PERSIST);
      options->persist_tun = true;
    }
  else if (streq (p[0], "persist-key"))
    {
      VERIFY_PERMISSION (OPT_P_PERSIST);
      options->persist_key = true;
    }
  else if (streq (p[0], "persist-local-ip"))
    {
      VERIFY_PERMISSION (OPT_P_PERSIST_IP);
      options->persist_local_ip = true;
    }
  else if (streq (p[0], "persist-remote-ip"))
    {
      VERIFY_PERMISSION (OPT_P_PERSIST_IP);
      options->persist_remote_ip = true;
    }
#ifdef ENABLE_CLIENT_NAT
  else if (streq (p[0], "client-nat") && p[1] && p[2] && p[3] && p[4])
    {
      VERIFY_PERMISSION (OPT_P_ROUTE);
      cnol_check_alloc (options);
      add_client_nat_to_option_list(options->client_nat, p[1], p[2], p[3], p[4], msglevel);
    }
#endif
  else if (streq (p[0], "route") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_ROUTE);
      rol_check_alloc (options);
      if (pull_mode)
	{
	  if (!ip_or_dns_addr_safe (p[1], options->allow_pull_fqdn) && !is_special_addr (p[1])) /* FQDN -- may be DNS name */
	    {
	      msg (msglevel, "route parameter network/IP '%s' must be a valid address", p[1]);
	      goto err;
	    }
	  if (p[2] && !ip_addr_dotted_quad_safe (p[2])) /* FQDN -- must be IP address */
	    {
	      msg (msglevel, "route parameter netmask '%s' must be an IP address", p[2]);
	      goto err;
	    }
	  if (p[3] && !ip_or_dns_addr_safe (p[3], options->allow_pull_fqdn) && !is_special_addr (p[3])) /* FQDN -- may be DNS name */
	    {
	      msg (msglevel, "route parameter gateway '%s' must be a valid address", p[3]);
	      goto err;
	    }
	}
      add_route_to_option_list (options->routes, p[1], p[2], p[3], p[4]);
    }
  else if (streq (p[0], "route-ipv6") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_ROUTE);
      rol6_check_alloc (options);
      if (pull_mode)
	{
	  if (!ipv6_addr_safe_hexplusbits (p[1]))
	    {
	      msg (msglevel, "route-ipv6 parameter network/IP '%s' must be a valid address", p[1]);
	      goto err;
	    }
	  if (p[2] && !ipv6_addr_safe (p[2]))
	    {
	      msg (msglevel, "route-ipv6 parameter gateway '%s' must be a valid address", p[2]);
	      goto err;
	    }
	  /* p[3] is metric, if present */
	}
      add_route_ipv6_to_option_list (options->routes_ipv6, p[1], p[2], p[3]);
    }
  else if (streq (p[0], "max-routes") && p[1])
    {
      int max_routes;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      max_routes = atoi (p[1]);
      if (max_routes < 0 || max_routes > 100000000)
	{
	  msg (msglevel, "--max-routes parameter is out of range");
	  goto err;
	}
      if (options->routes || options->routes_ipv6)
        {
          msg (msglevel, "--max-routes must to be specifed before any route/route-ipv6/redirect-gateway option");
          goto err;
        }
      options->max_routes = max_routes;
    }
  else if (streq (p[0], "route-gateway") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_ROUTE_EXTRAS);
      if (streq (p[1], "dhcp"))
	{
	  options->route_gateway_via_dhcp = true;
	}
      else
	{
	  if (ip_or_dns_addr_safe (p[1], options->allow_pull_fqdn) || is_special_addr (p[1])) /* FQDN -- may be DNS name */
	    {
	      options->route_default_gateway = p[1];
	    }
	  else
	    {
	      msg (msglevel, "route-gateway parm '%s' must be a valid address", p[1]);
	      goto err;
	    }
	}
    }
  else if (streq (p[0], "route-metric") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_ROUTE);
      options->route_default_metric = positive_atoi (p[1]);
    }
  else if (streq (p[0], "route-delay"))
    {
      VERIFY_PERMISSION (OPT_P_ROUTE_EXTRAS);
      options->route_delay_defined = true;
      if (p[1])
	{
	  options->route_delay = positive_atoi (p[1]);
	  if (p[2])
	    {
	      options->route_delay_window = positive_atoi (p[2]);
	    }
	}
      else
	{
	  options->route_delay = 0;
	}
    }
  else if (streq (p[0], "route-up") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_SCRIPT);
      if (!no_more_than_n_args (msglevel, p, 2, NM_QUOTE_HINT))
	goto err;
      set_user_script (options, &options->route_script, p[1], "route-up", false);
    }
  else if (streq (p[0], "route-pre-down") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_SCRIPT);
      if (!no_more_than_n_args (msglevel, p, 2, NM_QUOTE_HINT))
	goto err;
      set_user_script (options,
		       &options->route_predown_script,
		       p[1],
		       "route-pre-down", true);
    }
  else if (streq (p[0], "route-noexec"))
    {
      VERIFY_PERMISSION (OPT_P_SCRIPT);
      options->route_noexec = true;
    }
  else if (streq (p[0], "route-nopull"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->route_nopull = true;
    }
  else if (streq (p[0], "allow-pull-fqdn"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->allow_pull_fqdn = true;
    }
  else if (streq (p[0], "redirect-gateway") || streq (p[0], "redirect-private"))
    {
      int j;
      VERIFY_PERMISSION (OPT_P_ROUTE);
      rol_check_alloc (options);
      if (streq (p[0], "redirect-gateway"))
	options->routes->flags |= RG_REROUTE_GW;
      for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j)
	{
	  if (streq (p[j], "local"))
	    options->routes->flags |= RG_LOCAL;
	  else if (streq (p[j], "autolocal"))
	    options->routes->flags |= RG_AUTO_LOCAL;
	  else if (streq (p[j], "def1"))
	    options->routes->flags |= RG_DEF1;
	  else if (streq (p[j], "bypass-dhcp"))
	    options->routes->flags |= RG_BYPASS_DHCP;
	  else if (streq (p[j], "bypass-dns"))
	    options->routes->flags |= RG_BYPASS_DNS;
	  else if (streq (p[j], "block-local"))
	    options->routes->flags |= RG_BLOCK_LOCAL;
	  else
	    {
	      msg (msglevel, "unknown --%s flag: %s", p[0], p[j]);
	      goto err;
	    }
	}
      options->routes->flags |= RG_ENABLE;
    }
  else if (streq (p[0], "remote-random-hostname"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->sockflags |= SF_HOST_RANDOMIZE;
    }
  else if (streq (p[0], "setenv") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (streq (p[1], "REMOTE_RANDOM_HOSTNAME"))
	{
	  options->sockflags |= SF_HOST_RANDOMIZE;
	}
      else if (streq (p[1], "GENERIC_CONFIG"))
	{
	  msg (msglevel, "this is a generic configuration and cannot directly be used");
	  goto err;
	}
#ifdef ENABLE_PUSH_PEER_INFO
      else if (streq (p[1], "PUSH_PEER_INFO"))
	{
	  options->push_peer_info = true;
	}
#endif
#if P2MP
      else if (streq (p[1], "SERVER_POLL_TIMEOUT") && p[2])
	{
	  options->server_poll_timeout = positive_atoi(p[2]);
	}
#endif
      else
	{
	  if (streq (p[1], "FORWARD_COMPATIBLE") && p[2] && streq (p[2], "1"))
	    {
	      options->forward_compatible = true;
	      msglevel_fc = msglevel_forward_compatible (options, msglevel);
	    }
	  setenv_str (es, p[1], p[2] ? p[2] : "");
	}
    }
  else if (streq (p[0], "setenv-safe") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_SETENV);
      setenv_str_safe (es, p[1], p[2] ? p[2] : "");
    }
  else if (streq (p[0], "script-security") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      script_security = atoi (p[1]);
    }
  else if (streq (p[0], "mssfix"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);
      if (p[1])
	{
	  options->ce.mssfix = positive_atoi (p[1]);
	}
      else
	options->ce.mssfix_default = true;

    }
#ifdef ENABLE_OCC
  else if (streq (p[0], "disable-occ"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->occ = false;
    }
#endif
#if P2MP
#if P2MP_SERVER
  else if (streq (p[0], "server") && p[1] && p[2])
    {
      const int lev = M_WARN;
      bool error = false;
      in_addr_t network, netmask;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      network = get_ip_addr (p[1], lev, &error);
      netmask = get_ip_addr (p[2], lev, &error);
      if (error || !network || !netmask)
	{
	  msg (msglevel, "error parsing --server parameters");
	  goto err;
	}
      options->server_defined = true;
      options->server_network = network;
      options->server_netmask = netmask;

      if (p[3])
	{
	  if (streq (p[3], "nopool"))
	    options->server_flags |= SF_NOPOOL;
	  else
	    {
	      msg (msglevel, "error parsing --server: %s is not a recognized flag", p[3]);
	      goto err;
	    }
	}
    }
  else if (streq (p[0], "server-ipv6") && p[1] )
    {
      const int lev = M_WARN;
      struct in6_addr network;
      unsigned int netbits = 0;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      if ( ! get_ipv6_addr (p[1], &network, &netbits, NULL, lev) )
	{
	  msg (msglevel, "error parsing --server-ipv6 parameter");
	  goto err;
	}
      if ( netbits < 64 || netbits > 112 )
	{
	  msg( msglevel, "--server-ipv6 settings: only /64../112 supported right now (not /%d)", netbits );
	  goto err;
	}
      options->server_ipv6_defined = true;
      options->server_network_ipv6 = network;
      options->server_netbits_ipv6 = netbits;

      if (p[2])		/* no "nopool" options or similar for IPv6 */
	{
	  msg (msglevel, "error parsing --server-ipv6: %s is not a recognized flag", p[3]);
	  goto err;
	}
    }
  else if (streq (p[0], "server-bridge") && p[1] && p[2] && p[3] && p[4])
    {
      const int lev = M_WARN;
      bool error = false;
      in_addr_t ip, netmask, pool_start, pool_end;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      ip = get_ip_addr (p[1], lev, &error);
      netmask = get_ip_addr (p[2], lev, &error);
      pool_start = get_ip_addr (p[3], lev, &error);
      pool_end = get_ip_addr (p[4], lev, &error);
      if (error || !ip || !netmask || !pool_start || !pool_end)
	{
	  msg (msglevel, "error parsing --server-bridge parameters");
	  goto err;
	}
      options->server_bridge_defined = true;
      options->server_bridge_ip = ip;
      options->server_bridge_netmask = netmask;
      options->server_bridge_pool_start = pool_start;
      options->server_bridge_pool_end = pool_end;
    }
  else if (streq (p[0], "server-bridge") && p[1] && streq (p[1], "nogw"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->server_bridge_proxy_dhcp = true;
      options->server_flags |= SF_NO_PUSH_ROUTE_GATEWAY;
    }
  else if (streq (p[0], "server-bridge") && !p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->server_bridge_proxy_dhcp = true;
    }
  else if (streq (p[0], "push") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_PUSH);
      push_options (options, &p[1], msglevel, &options->gc);
    }
  else if (streq (p[0], "push-reset"))
    {
      VERIFY_PERMISSION (OPT_P_INSTANCE);
      push_reset (options);
    }
  else if (streq (p[0], "ifconfig-pool") && p[1] && p[2])
    {
      const int lev = M_WARN;
      bool error = false;
      in_addr_t start, end, netmask=0;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      start = get_ip_addr (p[1], lev, &error);
      end = get_ip_addr (p[2], lev, &error);
      if (p[3])
	{
	  netmask = get_ip_addr (p[3], lev, &error);
	}
      if (error)
	{
	  msg (msglevel, "error parsing --ifconfig-pool parameters");
	  goto err;
	}
      if (!ifconfig_pool_verify_range (msglevel, start, end))
	goto err;

      options->ifconfig_pool_defined = true;
      options->ifconfig_pool_start = start;
      options->ifconfig_pool_end = end;
      if (netmask)
	options->ifconfig_pool_netmask = netmask;
    }
  else if (streq (p[0], "ifconfig-pool-persist") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->ifconfig_pool_persist_filename = p[1];
      if (p[2])
	{
	  options->ifconfig_pool_persist_refresh_freq = positive_atoi (p[2]);
	}
    }
  else if (streq (p[0], "ifconfig-pool-linear"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->topology = TOP_P2P;
    }
  else if (streq (p[0], "ifconfig-ipv6-pool") && p[1] )
    {
      const int lev = M_WARN;
      struct in6_addr network;
      unsigned int netbits = 0;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      if ( ! get_ipv6_addr (p[1], &network, &netbits, NULL, lev ) )
	{
	  msg (msglevel, "error parsing --ifconfig-ipv6-pool parameters");
	  goto err;
	}
      if ( netbits < 64 || netbits > 112 )
	{
	  msg( msglevel, "--ifconfig-ipv6-pool settings: only /64../112 supported right now (not /%d)", netbits );
	  goto err;
	}

      options->ifconfig_ipv6_pool_defined = true;
      options->ifconfig_ipv6_pool_base = network;
      options->ifconfig_ipv6_pool_netbits = netbits;
    }
  else if (streq (p[0], "hash-size") && p[1] && p[2])
    {
      int real, virtual;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      real = atoi (p[1]);
      virtual = atoi (p[2]);
      if (real < 1 || virtual < 1)
	{
	  msg (msglevel, "--hash-size sizes must be >= 1 (preferably a power of 2)");
	  goto err;
	}
      options->real_hash_size = real;
      options->virtual_hash_size = real;
    }
  else if (streq (p[0], "connect-freq") && p[1] && p[2])
    {
      int cf_max, cf_per;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      cf_max = atoi (p[1]);
      cf_per = atoi (p[2]);
      if (cf_max < 0 || cf_per < 0)
	{
	  msg (msglevel, "--connect-freq parms must be > 0");
	  goto err;
	}
      options->cf_max = cf_max;
      options->cf_per = cf_per;
    }
  else if (streq (p[0], "max-clients") && p[1])
    {
      int max_clients;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      max_clients = atoi (p[1]);
      if (max_clients < 0)
	{
	  msg (msglevel, "--max-clients must be at least 1");
	  goto err;
	}
      options->max_clients = max_clients;
    }
  else if (streq (p[0], "max-routes-per-client") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_INHERIT);
      options->max_routes_per_client = max_int (atoi (p[1]), 1);
    }
  else if (streq (p[0], "client-cert-not-required"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->ssl_flags |= SSLF_CLIENT_CERT_NOT_REQUIRED;
    }
  else if (streq (p[0], "username-as-common-name"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->ssl_flags |= SSLF_USERNAME_AS_COMMON_NAME;
    }
  else if (streq (p[0], "auth-user-pass-optional"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->ssl_flags |= SSLF_AUTH_USER_PASS_OPTIONAL;
    }
  else if (streq (p[0], "opt-verify"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->ssl_flags |= SSLF_OPT_VERIFY;
    }
  else if (streq (p[0], "auth-user-pass-verify") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_SCRIPT);
      if (!no_more_than_n_args (msglevel, p, 3, NM_QUOTE_HINT))
	goto err;
      if (p[2])
	{
	  if (streq (p[2], "via-env"))
	    options->auth_user_pass_verify_script_via_file = false;
	  else if (streq (p[2], "via-file"))
	    options->auth_user_pass_verify_script_via_file = true;
	  else
	    {
	      msg (msglevel, "second parm to --auth-user-pass-verify must be 'via-env' or 'via-file'");
	      goto err;
	    }
	}
      else
	{
	  msg (msglevel, "--auth-user-pass-verify requires a second parameter ('via-env' or 'via-file')");
	  goto err;
	}
      set_user_script (options,
		       &options->auth_user_pass_verify_script,
		       p[1], "auth-user-pass-verify", true);
    }
  else if (streq (p[0], "client-connect") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_SCRIPT);
      if (!no_more_than_n_args (msglevel, p, 2, NM_QUOTE_HINT))
	goto err;
      set_user_script (options, &options->client_connect_script,
		       p[1], "client-connect", true);
    }
  else if (streq (p[0], "client-disconnect") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_SCRIPT);
      if (!no_more_than_n_args (msglevel, p, 2, NM_QUOTE_HINT))
	goto err;
      set_user_script (options, &options->client_disconnect_script,
		       p[1], "client-disconnect", true);
    }
  else if (streq (p[0], "learn-address") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_SCRIPT);
      if (!no_more_than_n_args (msglevel, p, 2, NM_QUOTE_HINT))
	goto err;
      set_user_script (options, &options->learn_address_script,
		       p[1], "learn-address", true);
    }
  else if (streq (p[0], "tmp-dir") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->tmp_dir = p[1];
    }
  else if (streq (p[0], "client-config-dir") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->client_config_dir = p[1];
    }
  else if (streq (p[0], "ccd-exclusive"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->ccd_exclusive = true;
    }
  else if (streq (p[0], "bcast-buffers") && p[1])
    {
      int n_bcast_buf;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      n_bcast_buf = atoi (p[1]);
      if (n_bcast_buf < 1)
	msg (msglevel, "--bcast-buffers parameter must be > 0");
      options->n_bcast_buf = n_bcast_buf;
    }
  else if (streq (p[0], "tcp-queue-limit") && p[1])
    {
      int tcp_queue_limit;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      tcp_queue_limit = atoi (p[1]);
      if (tcp_queue_limit < 1)
	msg (msglevel, "--tcp-queue-limit parameter must be > 0");
      options->tcp_queue_limit = tcp_queue_limit;
    }
#if PORT_SHARE
  else if (streq (p[0], "port-share") && p[1] && p[2])
    {
      int port;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      port = atoi (p[2]);
      if (!legal_ipv4_port (port))
	{
	  msg (msglevel, "port number associated with --port-share directive is out of range");
	  goto err;
	}

      options->port_share_host = p[1];
      options->port_share_port = port;
      options->port_share_journal_dir = p[3];
    }
#endif
  else if (streq (p[0], "client-to-client"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->enable_c2c = true;
    }
  else if (streq (p[0], "duplicate-cn"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->duplicate_cn = true;
    }
  else if (streq (p[0], "iroute") && p[1])
    {
      const char *netmask = NULL;

      VERIFY_PERMISSION (OPT_P_INSTANCE);
      if (p[2])
	{
	  netmask = p[2];
	}
      option_iroute (options, p[1], netmask, msglevel);
    }
  else if (streq (p[0], "iroute-ipv6") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_INSTANCE);
      option_iroute_ipv6 (options, p[1], msglevel);
    }
  else if (streq (p[0], "ifconfig-push") && p[1] && p[2])
    {
      in_addr_t local, remote_netmask;

      VERIFY_PERMISSION (OPT_P_INSTANCE);
      local = getaddr (GETADDR_HOST_ORDER|GETADDR_RESOLVE, p[1], 0, NULL, NULL);
      remote_netmask = getaddr (GETADDR_HOST_ORDER|GETADDR_RESOLVE, p[2], 0, NULL, NULL);
      if (local && remote_netmask)
	{
	  options->push_ifconfig_defined = true;
	  options->push_ifconfig_local = local;
	  options->push_ifconfig_remote_netmask = remote_netmask;
#ifdef ENABLE_CLIENT_NAT
	  if (p[3])
	    options->push_ifconfig_local_alias = getaddr (GETADDR_HOST_ORDER|GETADDR_RESOLVE, p[3], 0, NULL, NULL);
#endif
	}
      else
	{
	  msg (msglevel, "cannot parse --ifconfig-push addresses");
	  goto err;
	}
    }
  else if (streq (p[0], "ifconfig-push-constraint") && p[1] && p[2])
    {
      in_addr_t network, netmask;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      network = getaddr (GETADDR_HOST_ORDER|GETADDR_RESOLVE, p[1], 0, NULL, NULL);
      netmask = getaddr (GETADDR_HOST_ORDER, p[2], 0, NULL, NULL);
      if (network && netmask)
	{
	  options->push_ifconfig_constraint_defined = true;
	  options->push_ifconfig_constraint_network = network;
	  options->push_ifconfig_constraint_netmask = netmask;
	}
      else
	{
	  msg (msglevel, "cannot parse --ifconfig-push-constraint addresses");
	  goto err;
	}
    }
  else if (streq (p[0], "ifconfig-ipv6-push") && p[1] )
    {
      struct in6_addr local, remote;
      unsigned int netbits;

      VERIFY_PERMISSION (OPT_P_INSTANCE);

      if ( ! get_ipv6_addr( p[1], &local, &netbits, NULL, msglevel ) )
	{
	  msg (msglevel, "cannot parse --ifconfig-ipv6-push addresses");
	  goto err;
	}

      if ( p[2] )
	{
	  if ( !get_ipv6_addr( p[2], &remote, NULL, NULL, msglevel ) )
	    {
	      msg( msglevel, "cannot parse --ifconfig-ipv6-push addresses");
	      goto err;
	    }
	}
      else
	{
	  if ( ! options->ifconfig_ipv6_local ||
	       ! get_ipv6_addr( options->ifconfig_ipv6_local, &remote, 
				NULL, NULL, msglevel ) )
	    {
	      msg( msglevel, "second argument to --ifconfig-ipv6-push missing and no global --ifconfig-ipv6 address set");
	      goto err;
	    }
	}

      options->push_ifconfig_ipv6_defined = true;
      options->push_ifconfig_ipv6_local = local;
      options->push_ifconfig_ipv6_netbits = netbits;
      options->push_ifconfig_ipv6_remote = remote;
    }
  else if (streq (p[0], "disable"))
    {
      VERIFY_PERMISSION (OPT_P_INSTANCE);
      options->disable = true;
    }
  else if (streq (p[0], "tcp-nodelay"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->server_flags |= SF_TCP_NODELAY_HELPER;
    }
  else if (streq (p[0], "stale-routes-check") && p[1])
    {
      int ageing_time, check_interval;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      ageing_time = atoi (p[1]);
      if (p[2])
        check_interval = atoi (p[2]);
      else
        check_interval = ageing_time;

      if (ageing_time < 1 || check_interval < 1)
        {
        msg (msglevel, "--stale-routes-check aging time and check interval must be >= 1");
        goto err;
        }
      options->stale_routes_ageing_time  = ageing_time;
      options->stale_routes_check_interval = check_interval;
    }
#endif /* P2MP_SERVER */

  else if (streq (p[0], "client"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->client = true;
    }
  else if (streq (p[0], "pull"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->pull = true;
    }
  else if (streq (p[0], "push-continuation") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_PULL_MODE);
      options->push_continuation = atoi(p[1]);
    }
  else if (streq (p[0], "server-poll-timeout") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->server_poll_timeout = positive_atoi(p[1]);
    }
  else if (streq (p[0], "auth-user-pass"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (p[1])
	{
	  options->auth_user_pass_file = p[1];
	}
      else
	options->auth_user_pass_file = "stdin";
    }
  else if (streq (p[0], "auth-retry") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      auth_retry_set (msglevel, p[1]);
    }
#ifdef ENABLE_CLIENT_CR
  else if (streq (p[0], "static-challenge") && p[1] && p[2])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->sc_info.challenge_text = p[1];
      if (atoi(p[2]))
	options->sc_info.flags |= SC_ECHO;
    }
#endif
#endif
#ifdef WIN32
  else if (streq (p[0], "win-sys") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (streq (p[1], "env"))
	msg (M_INFO, "NOTE: --win-sys env is default from OpenVPN v2.3.	 "
	     "This entry will now be ignored.  "
	     "Please remove this entry from your configuration file.");
      else
	set_win_sys_path (p[1], es);
    }
  else if (streq (p[0], "route-method") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_ROUTE_EXTRAS);
      if (streq (p[1], "adaptive"))
	options->route_method = ROUTE_METHOD_ADAPTIVE;
      else if (streq (p[1], "ipapi"))
	options->route_method = ROUTE_METHOD_IPAPI;
      else if (streq (p[1], "exe"))
	options->route_method = ROUTE_METHOD_EXE;
      else
	{
	  msg (msglevel, "--route method must be 'adaptive', 'ipapi', or 'exe'");
	  goto err;
	}
    }
  else if (streq (p[0], "ip-win32") && p[1])
    {
      const int index = ascii2ipset (p[1]);
      struct tuntap_options *to = &options->tuntap_options;

      VERIFY_PERMISSION (OPT_P_IPWIN32);

      if (index < 0)
	{
	  msg (msglevel,
	       "Bad --ip-win32 method: '%s'.  Allowed methods: %s",
	       p[1],
	       ipset2ascii_all (&gc));
	  goto err;
	}

      if (index == IPW32_SET_ADAPTIVE)
	options->route_delay_window = IPW32_SET_ADAPTIVE_DELAY_WINDOW;

      if (index == IPW32_SET_DHCP_MASQ)
	{
	  if (p[2])
	    {
	      if (!streq (p[2], "default"))
		{
		  int offset = atoi (p[2]);

		  if (!(offset > -256 && offset < 256))
		    {
		      msg (msglevel, "--ip-win32 dynamic [offset] [lease-time]: offset (%d) must be > -256 and < 256", offset);
		      goto err;
		    }

		  to->dhcp_masq_custom_offset = true;
		  to->dhcp_masq_offset = offset;
		}

	      if (p[3])
		{
		  const int min_lease = 30;
		  int lease_time;
		  lease_time = atoi (p[3]);
		  if (lease_time < min_lease)
		    {
		      msg (msglevel, "--ip-win32 dynamic [offset] [lease-time]: lease time parameter (%d) must be at least %d seconds", lease_time, min_lease);
		      goto err;
		    }
		  to->dhcp_lease_time = lease_time;
		}
	    }
	}
      to->ip_win32_type = index;
      to->ip_win32_defined = true; 
    }
  else if (streq (p[0], "dhcp-option") && p[1])
    {
      struct tuntap_options *o = &options->tuntap_options;
      VERIFY_PERMISSION (OPT_P_IPWIN32);

      if (streq (p[1], "DOMAIN") && p[2])
	{
	  o->domain = p[2];
	}
      else if (streq (p[1], "NBS") && p[2])
	{
	  o->netbios_scope = p[2];
	}
      else if (streq (p[1], "NBT") && p[2])
	{
	  int t;
	  t = atoi (p[2]);
	  if (!(t == 1 || t == 2 || t == 4 || t == 8))
	    {
	      msg (msglevel, "--dhcp-option NBT: parameter (%d) must be 1, 2, 4, or 8", t);
	      goto err;
	    }
	  o->netbios_node_type = t;
	}
      else if (streq (p[1], "DNS") && p[2])
	{
	  dhcp_option_address_parse ("DNS", p[2], o->dns, &o->dns_len, msglevel);
	}
      else if (streq (p[1], "WINS") && p[2])
	{
	  dhcp_option_address_parse ("WINS", p[2], o->wins, &o->wins_len, msglevel);
	}
      else if (streq (p[1], "NTP") && p[2])
	{
	  dhcp_option_address_parse ("NTP", p[2], o->ntp, &o->ntp_len, msglevel);
	}
      else if (streq (p[1], "NBDD") && p[2])
	{
	  dhcp_option_address_parse ("NBDD", p[2], o->nbdd, &o->nbdd_len, msglevel);
	}
      else if (streq (p[1], "DISABLE-NBT"))
	{
	  o->disable_nbt = 1;
	}
      else
	{
	  msg (msglevel, "--dhcp-option: unknown option type '%s' or missing parameter", p[1]);
	  goto err;
	}
      o->dhcp_options = true;
    }
  else if (streq (p[0], "show-adapters"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      show_tap_win_adapters (M_INFO|M_NOPREFIX, M_WARN|M_NOPREFIX);
      openvpn_exit (OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }
  else if (streq (p[0], "show-net"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      show_routes (M_INFO|M_NOPREFIX);
      show_adapters (M_INFO|M_NOPREFIX);
      openvpn_exit (OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }
  else if (streq (p[0], "show-net-up"))
    {
      VERIFY_PERMISSION (OPT_P_UP);
      options->show_net_up = true;
    }
  else if (streq (p[0], "tap-sleep") && p[1])
    {
      int s;
      VERIFY_PERMISSION (OPT_P_IPWIN32);
      s = atoi (p[1]);
      if (s < 0 || s >= 256)
	{
	  msg (msglevel, "--tap-sleep parameter must be between 0 and 255");
	  goto err;
	}
      options->tuntap_options.tap_sleep = s;
    }
  else if (streq (p[0], "dhcp-renew"))
    {
      VERIFY_PERMISSION (OPT_P_IPWIN32);
      options->tuntap_options.dhcp_renew = true;
    }
  else if (streq (p[0], "dhcp-pre-release"))
    {
      VERIFY_PERMISSION (OPT_P_IPWIN32);
      options->tuntap_options.dhcp_pre_release = true;
    }
  else if (streq (p[0], "dhcp-release"))
    {
      VERIFY_PERMISSION (OPT_P_IPWIN32);
      options->tuntap_options.dhcp_release = true;
    }
  else if (streq (p[0], "dhcp-internal") && p[1]) /* standalone method for internal use */
    {
      unsigned int adapter_index;
      VERIFY_PERMISSION (OPT_P_GENERAL);
      set_debug_level (options->verbosity, SDL_CONSTRAIN);
      adapter_index = atou (p[1]);
      sleep (options->tuntap_options.tap_sleep);
      if (options->tuntap_options.dhcp_pre_release)
	dhcp_release_by_adapter_index (adapter_index);
      if (options->tuntap_options.dhcp_renew)
	dhcp_renew_by_adapter_index (adapter_index);
      openvpn_exit (OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }
  else if (streq (p[0], "register-dns"))
    {
      VERIFY_PERMISSION (OPT_P_IPWIN32);
      options->tuntap_options.register_dns = true;
    }
  else if (streq (p[0], "rdns-internal"))
     /* standalone method for internal use
      *
      * (if --register-dns is set, openvpn needs to call itself in a
      *  sub-process to execute the required functions in a non-blocking
      *  way, and uses --rdns-internal to signal that to itself)
      */
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      set_debug_level (options->verbosity, SDL_CONSTRAIN);
      if (options->tuntap_options.register_dns)
	ipconfig_register_dns (NULL);
      openvpn_exit (OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }
  else if (streq (p[0], "show-valid-subnets"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      show_valid_win32_tun_subnets ();
      openvpn_exit (OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }
  else if (streq (p[0], "pause-exit"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      set_pause_exit_win32 ();
    }
  else if (streq (p[0], "service") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->exit_event_name = p[1];
      if (p[2])
	{
	  options->exit_event_initial_state = (atoi(p[2]) != 0);
	}
    }
  else if (streq (p[0], "allow-nonadmin"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      tap_allow_nonadmin_access (p[1]);
      openvpn_exit (OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }
  else if (streq (p[0], "user") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      msg (M_WARN, "NOTE: --user option is not implemented on Windows");
    }
  else if (streq (p[0], "group") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      msg (M_WARN, "NOTE: --group option is not implemented on Windows");
    }
#else
  else if (streq (p[0], "user") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->username = p[1];
    }
  else if (streq (p[0], "group") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->groupname = p[1];
    }
  else if (streq (p[0], "dhcp-option") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_IPWIN32);
      foreign_option (options, p, 3, es);
    }
  else if (streq (p[0], "route-method") && p[1]) /* ignore when pushed to non-Windows OS */
    {
      VERIFY_PERMISSION (OPT_P_ROUTE_EXTRAS);
    }
#endif
#if PASSTOS_CAPABILITY
  else if (streq (p[0], "passtos"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->passtos = true;
    }
#endif
#ifdef ENABLE_LZO
  else if (streq (p[0], "comp-lzo"))
    {
      VERIFY_PERMISSION (OPT_P_COMP);
      if (p[1])
	{
	  if (streq (p[1], "yes"))
	    options->lzo = LZO_SELECTED|LZO_ON;
	  else if (streq (p[1], "no"))
	    options->lzo = LZO_SELECTED;
	  else if (streq (p[1], "adaptive"))
	    options->lzo = LZO_SELECTED|LZO_ON|LZO_ADAPTIVE;
	  else
	    {
	      msg (msglevel, "bad comp-lzo option: %s -- must be 'yes', 'no', or 'adaptive'", p[1]);
	      goto err;
	    }
	}
      else
	options->lzo = LZO_SELECTED|LZO_ON|LZO_ADAPTIVE;
    }
  else if (streq (p[0], "comp-noadapt"))
    {
      VERIFY_PERMISSION (OPT_P_COMP);
      options->lzo &= ~LZO_ADAPTIVE;
    }
#endif /* ENABLE_LZO */
#ifdef ENABLE_CRYPTO
  else if (streq (p[0], "show-ciphers"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->show_ciphers = true;
    }
  else if (streq (p[0], "show-digests"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->show_digests = true;
    }
  else if (streq (p[0], "show-engines"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->show_engines = true;
    }
  else if (streq (p[0], "key-direction") && p[1])
    {
      int key_direction;

      key_direction = ascii2keydirection (msglevel, p[1]);
      if (key_direction >= 0)
	options->key_direction = key_direction;
      else
	goto err;
    }
  else if (streq (p[0], "secret") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (streq (p[1], INLINE_FILE_TAG) && p[2])
	{
	  options->shared_secret_file_inline = p[2];
	}
      else
      if (p[2])
	{
	  int key_direction;

	  key_direction = ascii2keydirection (msglevel, p[2]);
	  if (key_direction >= 0)
	    options->key_direction = key_direction;
	  else
	    goto err;
	}
      options->shared_secret_file = p[1];
    }
  else if (streq (p[0], "genkey"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->genkey = true;
    }
  else if (streq (p[0], "auth") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_CRYPTO);
      options->authname_defined = true;
      options->authname = p[1];
      if (streq (options->authname, "none"))
	{
	  options->authname_defined = false;
	  options->authname = NULL;
	}
    }
  else if (streq (p[0], "auth"))
    {
      VERIFY_PERMISSION (OPT_P_CRYPTO);
      options->authname_defined = true;
    }
  else if (streq (p[0], "cipher") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_CRYPTO);
      options->ciphername_defined = true;
      options->ciphername = p[1];
      if (streq (options->ciphername, "none"))
	{
	  options->ciphername_defined = false;
	  options->ciphername = NULL;
	}
    }
  else if (streq (p[0], "cipher"))
    {
      VERIFY_PERMISSION (OPT_P_CRYPTO);
      options->ciphername_defined = true;
    }
  else if (streq (p[0], "prng") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_CRYPTO);
      if (streq (p[1], "none"))
	options->prng_hash = NULL;
      else
	options->prng_hash = p[1];
      if (p[2])
	{
	  const int sl = atoi (p[2]);
	  if (sl >= NONCE_SECRET_LEN_MIN && sl <= NONCE_SECRET_LEN_MAX)
	    {
	      options->prng_nonce_secret_len = sl;
	    }
	  else
	    {
	      msg (msglevel, "prng parameter nonce_secret_len must be between %d and %d",
		   NONCE_SECRET_LEN_MIN, NONCE_SECRET_LEN_MAX);
	      goto err;
	    }
	}
    }
  else if (streq (p[0], "no-replay"))
    {
      VERIFY_PERMISSION (OPT_P_CRYPTO);
      options->replay = false;
    }
  else if (streq (p[0], "replay-window"))
    {
      VERIFY_PERMISSION (OPT_P_CRYPTO);
      if (p[1])
	{
	  int replay_window;

	  replay_window = atoi (p[1]);
	  if (!(MIN_SEQ_BACKTRACK <= replay_window && replay_window <= MAX_SEQ_BACKTRACK))
	    {
	      msg (msglevel, "replay-window window size parameter (%d) must be between %d and %d",
		   replay_window,
		   MIN_SEQ_BACKTRACK,
		   MAX_SEQ_BACKTRACK);
	      goto err;
	    }
	  options->replay_window = replay_window;

	  if (p[2])
	    {
	      int replay_time;

	      replay_time = atoi (p[2]);
	      if (!(MIN_TIME_BACKTRACK <= replay_time && replay_time <= MAX_TIME_BACKTRACK))
		{
		  msg (msglevel, "replay-window time window parameter (%d) must be between %d and %d",
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
	  msg (msglevel, "replay-window option is missing window size parameter");
	  goto err;
	}
    }
  else if (streq (p[0], "mute-replay-warnings"))
    {
      VERIFY_PERMISSION (OPT_P_CRYPTO);
      options->mute_replay_warnings = true;
    }
  else if (streq (p[0], "no-iv"))
    {
      VERIFY_PERMISSION (OPT_P_CRYPTO);
      options->use_iv = false;
    }
  else if (streq (p[0], "replay-persist") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->packet_id_file = p[1];
    }
  else if (streq (p[0], "test-crypto"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->test_crypto = true;
    }
#ifndef ENABLE_CRYPTO_POLARSSL
  else if (streq (p[0], "engine"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (p[1])
	{
	  options->engine = p[1];
	}
      else
	options->engine = "auto";
    }  
#endif /* ENABLE_CRYPTO_POLARSSL */
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
  else if (streq (p[0], "keysize") && p[1])
    {
      int keysize;

      VERIFY_PERMISSION (OPT_P_CRYPTO);
      keysize = atoi (p[1]) / 8;
      if (keysize < 0 || keysize > MAX_CIPHER_KEY_LENGTH)
	{
	  msg (msglevel, "Bad keysize: %s", p[1]);
	  goto err;
	}
      options->keysize = keysize;
    }
#endif
#ifdef ENABLE_PREDICTION_RESISTANCE
  else if (streq (p[0], "use-prediction-resistance"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->use_prediction_resistance = true;
    }
#endif
#ifdef ENABLE_SSL
  else if (streq (p[0], "show-tls"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->show_tls_ciphers = true;
    }
  else if (streq (p[0], "tls-server"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->tls_server = true;
    }
  else if (streq (p[0], "tls-client"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->tls_client = true;
    }
  else if (streq (p[0], "ca") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->ca_file = p[1];
      if (streq (p[1], INLINE_FILE_TAG) && p[2])
	{
	  options->ca_file_inline = p[2];
	}
    }
#ifndef ENABLE_CRYPTO_POLARSSL
  else if (streq (p[0], "capath") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->ca_path = p[1];
    }
#endif /* ENABLE_CRYPTO_POLARSSL */
  else if (streq (p[0], "dh") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->dh_file = p[1];
      if (streq (p[1], INLINE_FILE_TAG) && p[2])
	{
	  options->dh_file_inline = p[2];
	}
    }
  else if (streq (p[0], "cert") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->cert_file = p[1];
      if (streq (p[1], INLINE_FILE_TAG) && p[2])
	{
	  options->cert_file_inline = p[2];
	}
    }
  else if (streq (p[0], "extra-certs") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->extra_certs_file = p[1];
      if (streq (p[1], INLINE_FILE_TAG) && p[2])
	{
	  options->extra_certs_file_inline = p[2];
	}
    }
  else if (streq (p[0], "verify-hash") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->verify_hash = parse_hash_fingerprint(p[1], SHA_DIGEST_LENGTH, msglevel, &options->gc);
    }
#ifdef ENABLE_CRYPTOAPI
  else if (streq (p[0], "cryptoapicert") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->cryptoapi_cert = p[1];
    }
#endif
  else if (streq (p[0], "key") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->priv_key_file = p[1];
      if (streq (p[1], INLINE_FILE_TAG) && p[2])
	{
	  options->priv_key_file_inline = p[2];
	}
    }
  else if (streq (p[0], "tls-version-min") && p[1])
    {
      int ver;
      VERIFY_PERMISSION (OPT_P_GENERAL);
      ver = tls_version_parse(p[1], p[2]);
      if (ver == TLS_VER_BAD)
	{
	  msg (msglevel, "unknown tls-version-min parameter: %s", p[1]);
          goto err;
	}
      options->ssl_flags &=
	  ~(SSLF_TLS_VERSION_MIN_MASK << SSLF_TLS_VERSION_MIN_SHIFT);
      options->ssl_flags |= (ver << SSLF_TLS_VERSION_MIN_SHIFT);
    }
  else if (streq (p[0], "tls-version-max") && p[1])
    {
      int ver;
      VERIFY_PERMISSION (OPT_P_GENERAL);
      ver = tls_version_parse(p[1], NULL);
      if (ver == TLS_VER_BAD)
	{
	  msg (msglevel, "unknown tls-version-max parameter: %s", p[1]);
          goto err;
	}
      options->ssl_flags &=
	  ~(SSLF_TLS_VERSION_MAX_MASK << SSLF_TLS_VERSION_MAX_SHIFT);
      options->ssl_flags |= (ver << SSLF_TLS_VERSION_MAX_SHIFT);
    }
#ifndef ENABLE_CRYPTO_POLARSSL
  else if (streq (p[0], "pkcs12") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->pkcs12_file = p[1];
      if (streq (p[1], INLINE_FILE_TAG) && p[2])
	{
	  options->pkcs12_file_inline = p[2];
	}
    }
#endif /* ENABLE_CRYPTO_POLARSSL */
  else if (streq (p[0], "askpass"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (p[1])
	{
	  options->key_pass_file = p[1];
	}
      else
	options->key_pass_file = "stdin";	
    }
  else if (streq (p[0], "auth-nocache"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      ssl_set_auth_nocache ();
    }
  else if (streq (p[0], "auth-token") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_ECHO);
      ssl_set_auth_token(p[1]);
#ifdef ENABLE_MANAGEMENT
      if (management)
	management_auth_token (management, p[1]);
#endif
    }
  else if (streq (p[0], "single-session"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->single_session = true;
    }
#ifdef ENABLE_PUSH_PEER_INFO
  else if (streq (p[0], "push-peer-info"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->push_peer_info = true;
    }
#endif
  else if (streq (p[0], "tls-exit"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->tls_exit = true;
    }
  else if (streq (p[0], "tls-cipher") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->cipher_list = p[1];
    }
  else if (streq (p[0], "crl-verify") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (p[2] && streq(p[2], "dir"))
	options->ssl_flags |= SSLF_CRL_VERIFY_DIR;
      options->crl_file = p[1];
    }
  else if (streq (p[0], "tls-verify") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_SCRIPT);
      if (!no_more_than_n_args (msglevel, p, 2, NM_QUOTE_HINT))
	goto err;
      set_user_script (options, &options->tls_verify,
		       string_substitute (p[1], ',', ' ', &options->gc),
		       "tls-verify", true);
    }
#ifndef ENABLE_CRYPTO_POLARSSL
  else if (streq (p[0], "tls-export-cert") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->tls_export_cert = p[1];
    }
#endif
  else if (streq (p[0], "compat-names"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (options->verify_x509_type != VERIFY_X509_NONE &&
          options->verify_x509_type != TLS_REMOTE_SUBJECT_DN &&
          options->verify_x509_type != TLS_REMOTE_SUBJECT_RDN_PREFIX)
        {
          msg (msglevel, "you cannot use --compat-names with --verify-x509-name");
          goto err;
        }
      msg (M_WARN, "DEPRECATED OPTION: --compat-names, please update your configuration");
      compat_flag (COMPAT_FLAG_SET | COMPAT_NAMES);
#if P2MP_SERVER
      if (p[1] && streq (p[1], "no-remapping"))
        compat_flag (COMPAT_FLAG_SET | COMPAT_NO_NAME_REMAPPING);
    }
  else if (streq (p[0], "no-name-remapping"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (options->verify_x509_type != VERIFY_X509_NONE &&
          options->verify_x509_type != TLS_REMOTE_SUBJECT_DN &&
          options->verify_x509_type != TLS_REMOTE_SUBJECT_RDN_PREFIX)
        {
          msg (msglevel, "you cannot use --no-name-remapping with --verify-x509-name");
          goto err;
        }
      msg (M_WARN, "DEPRECATED OPTION: --no-name-remapping, please update your configuration");
      compat_flag (COMPAT_FLAG_SET | COMPAT_NAMES);
      compat_flag (COMPAT_FLAG_SET | COMPAT_NO_NAME_REMAPPING);
#endif
    }
  else if (streq (p[0], "tls-remote") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);

      if (options->verify_x509_type != VERIFY_X509_NONE &&
          options->verify_x509_type != TLS_REMOTE_SUBJECT_DN &&
          options->verify_x509_type != TLS_REMOTE_SUBJECT_RDN_PREFIX)
        {
          msg (msglevel, "you cannot use --tls-remote with --verify-x509-name");
          goto err;
        }
      msg (M_WARN, "DEPRECATED OPTION: --tls-remote, please update your configuration");

      if (strlen (p[1]))
        {
          int is_username = (!strchr (p[1], '=') || !strstr (p[1], ", "));
          int type = TLS_REMOTE_SUBJECT_DN;
          if (p[1][0] != '/' && is_username)
            type = TLS_REMOTE_SUBJECT_RDN_PREFIX;

          /*
           * Enable legacy openvpn format for DNs that have not been converted
           * yet and --x509-username-field (not containing an '=' or ', ')
           */
          if (p[1][0] == '/' || is_username)
            compat_flag (COMPAT_FLAG_SET | COMPAT_NAMES);

          options->verify_x509_type = type;
          options->verify_x509_name = p[1];
        }
    }
  else if (streq (p[0], "verify-x509-name") && p[1] && strlen (p[1]))
    {
      int type = VERIFY_X509_SUBJECT_DN;
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (options->verify_x509_type == TLS_REMOTE_SUBJECT_DN ||
          options->verify_x509_type == TLS_REMOTE_SUBJECT_RDN_PREFIX)
        {
          msg (msglevel, "you cannot use --verify-x509-name with --tls-remote");
          goto err;
        }
      if (compat_flag (COMPAT_FLAG_QUERY | COMPAT_NAMES))
        {
          msg (msglevel, "you cannot use --verify-x509-name with "
                         "--compat-names or --no-name-remapping");
          goto err;
        }
      if (p[2])
        {
          if (streq (p[2], "subject"))
            type = VERIFY_X509_SUBJECT_DN;
          else if (streq (p[2], "name"))
            type = VERIFY_X509_SUBJECT_RDN;
          else if (streq (p[2], "name-prefix"))
            type = VERIFY_X509_SUBJECT_RDN_PREFIX;
          else
            {
              msg (msglevel, "unknown X.509 name type: %s", p[2]);
              goto err;
            }
        }
      options->verify_x509_type = type;
      options->verify_x509_name = p[1];
    }
  else if (streq (p[0], "ns-cert-type") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (streq (p[1], "server"))
	options->ns_cert_type = NS_CERT_CHECK_SERVER;
      else if (streq (p[1], "client"))
	options->ns_cert_type = NS_CERT_CHECK_CLIENT;
      else
	{
	  msg (msglevel, "--ns-cert-type must be 'client' or 'server'");
	  goto err;
	}
    }
#if OPENSSL_VERSION_NUMBER >= 0x00907000L || ENABLE_CRYPTO_POLARSSL
  else if (streq (p[0], "remote-cert-ku"))
    {
      int j;

      VERIFY_PERMISSION (OPT_P_GENERAL);

      for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j)
	sscanf (p[j], "%x", &(options->remote_cert_ku[j-1]));
    }
  else if (streq (p[0], "remote-cert-eku") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->remote_cert_eku = p[1];
    }
  else if (streq (p[0], "remote-cert-tls") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);

      if (streq (p[1], "server"))
	{
	  options->remote_cert_ku[0] = 0xa0;
	  options->remote_cert_ku[1] = 0x88;
	  options->remote_cert_eku = "TLS Web Server Authentication";
	}
      else if (streq (p[1], "client"))
	{
	  options->remote_cert_ku[0] = 0x80;
	  options->remote_cert_ku[1] = 0x08;
	  options->remote_cert_ku[2] = 0x88;
	  options->remote_cert_eku = "TLS Web Client Authentication";
	}
      else
	{
	  msg (msglevel, "--remote-cert-tls must be 'client' or 'server'");
	  goto err;
	}
    }
#endif	/* OPENSSL_VERSION_NUMBER */
  else if (streq (p[0], "tls-timeout") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_TLS_PARMS);
      options->tls_timeout = positive_atoi (p[1]);
    }
  else if (streq (p[0], "reneg-bytes") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_TLS_PARMS);
      options->renegotiate_bytes = positive_atoi (p[1]);
    }
  else if (streq (p[0], "reneg-pkts") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_TLS_PARMS);
      options->renegotiate_packets = positive_atoi (p[1]);
    }
  else if (streq (p[0], "reneg-sec") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_TLS_PARMS);
      options->renegotiate_seconds = positive_atoi (p[1]);
    }
  else if (streq (p[0], "hand-window") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_TLS_PARMS);
      options->handshake_window = positive_atoi (p[1]);
    }
  else if (streq (p[0], "tran-window") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_TLS_PARMS);
      options->transition_window = positive_atoi (p[1]);
    }
  else if (streq (p[0], "tls-auth") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (streq (p[1], INLINE_FILE_TAG) && p[2])
	{
	  options->tls_auth_file_inline = p[2];
	}
      else
      if (p[2])
	{
	  int key_direction;

	  key_direction = ascii2keydirection (msglevel, p[2]);
	  if (key_direction >= 0)
	    options->key_direction = key_direction;
	  else
	    goto err;
	}
      options->tls_auth_file = p[1];
    }
  else if (streq (p[0], "key-method") && p[1])
    {
      int key_method;

      VERIFY_PERMISSION (OPT_P_GENERAL);
      key_method = atoi (p[1]);
      if (key_method < KEY_METHOD_MIN || key_method > KEY_METHOD_MAX)
	{
	  msg (msglevel, "key_method parameter (%d) must be >= %d and <= %d",
	       key_method,
	       KEY_METHOD_MIN,
	       KEY_METHOD_MAX);
	  goto err;
	}
      options->key_method = key_method;
    }
#ifdef ENABLE_X509ALTUSERNAME
  else if (streq (p[0], "x509-username-field") && p[1])
    {
      /* This option used to automatically upcase the fieldname passed as the
       * option argument, e.g., "ou" became "OU". Now, this "helpfulness" is
       * fine-tuned by only upcasing Subject field attribute names which consist
       * of all lower-case characters. Mixed-case attributes such as
       * "emailAddress" are left as-is. An option parameter having the "ext:"
       * prefix for matching X.509v3 extended fields will also remain unchanged.
       */
      char *s = p[1];

      VERIFY_PERMISSION (OPT_P_GENERAL);
      if (strncmp("ext:", s, 4) != 0)
	{
	  size_t i = 0;
	  while (s[i] && !isupper(s[i])) i++;
	  if (strlen(s) == i)
	    {
	      while ((*s = toupper(*s)) != '\0') s++;
	      msg(M_WARN, "DEPRECATED FEATURE: automatically upcased the "
		  "--x509-username-field parameter to '%s'; please update your"
		  "configuration", p[1]);
	    }
	}
      options->x509_username_field = p[1];
    }
#endif /* ENABLE_X509ALTUSERNAME */
#endif /* ENABLE_SSL */
#endif /* ENABLE_CRYPTO */
#ifdef ENABLE_PKCS11
  else if (streq (p[0], "show-pkcs11-ids"))
    {
      char *provider =  p[1];
      bool cert_private = (p[2] == NULL ? false : ( atoi (p[2]) != 0 ));

#ifdef DEFAULT_PKCS11_MODULE
      if (!provider)
	provider = DEFAULT_PKCS11_MODULE;
      else if (!p[2])
        {
	  char *endp = NULL;
	  int i = strtol(provider, &endp, 10);

	  if (*endp == 0)
	    {
	      /* There was one argument, and it was purely numeric.
		 Interpret it as the cert_private argument */
	      provider = DEFAULT_PKCS11_MODULE;
	      cert_private = i;
	    }
        }
#else
      if (!provider)
	{
	  msg (msglevel, "--show-pkcs11-ids requires a provider parameter");
            goto err;
	}
#endif
      VERIFY_PERMISSION (OPT_P_GENERAL);

      set_debug_level (options->verbosity, SDL_CONSTRAIN);
      show_pkcs11_ids (provider, cert_private);
      openvpn_exit (OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }
  else if (streq (p[0], "pkcs11-providers") && p[1])
    {
      int j;
      
      VERIFY_PERMISSION (OPT_P_GENERAL);

      for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j)
      	options->pkcs11_providers[j-1] = p[j];
    }
  else if (streq (p[0], "pkcs11-protected-authentication"))
    {
      int j;

      VERIFY_PERMISSION (OPT_P_GENERAL);

      for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j)
        options->pkcs11_protected_authentication[j-1] = atoi (p[j]) != 0 ? 1 : 0;
    }
  else if (streq (p[0], "pkcs11-private-mode") && p[1])
    {
      int j;
      
      VERIFY_PERMISSION (OPT_P_GENERAL);

      for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j)
        sscanf (p[j], "%x", &(options->pkcs11_private_mode[j-1]));
    }
  else if (streq (p[0], "pkcs11-cert-private"))
    {
      int j;

      VERIFY_PERMISSION (OPT_P_GENERAL);

      for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j)
        options->pkcs11_cert_private[j-1] = atoi (p[j]) != 0 ? 1 : 0;
    }
   else if (streq (p[0], "pkcs11-pin-cache") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->pkcs11_pin_cache_period = atoi (p[1]);
    }
  else if (streq (p[0], "pkcs11-id") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->pkcs11_id = p[1];
    }
  else if (streq (p[0], "pkcs11-id-management"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->pkcs11_id_management = true;
    }
#endif
  else if (streq (p[0], "rmtun"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->persist_config = true;
      options->persist_mode = 0;
    }
  else if (streq (p[0], "mktun"))
    {
      VERIFY_PERMISSION (OPT_P_GENERAL);
      options->persist_config = true;
      options->persist_mode = 1;
    }
  else if (streq (p[0], "peer-id") && p[1])
    {
      VERIFY_PERMISSION (OPT_P_PEER_ID);
      options->use_peer_id = true;
      options->peer_id = atoi(p[1]);
    }
  else
    {
      int i;
      int msglevel= msglevel_fc;
      /* Check if an option is in --ignore-unknown-option and
         set warning level to non fatal */
      for(i=0; options->ignore_unknown_option && options->ignore_unknown_option[i]; i++)
        {
          if (streq(p[0], options->ignore_unknown_option[i]))
            {
              msglevel = M_WARN;
              break;
            }
        }
      if (file)
	msg (msglevel, "Unrecognized option or missing parameter(s) in %s:%d: %s (%s)", file, line, p[0], PACKAGE_VERSION);
      else
	msg (msglevel, "Unrecognized option or missing parameter(s): --%s (%s)", p[0], PACKAGE_VERSION);
    }
 err:
  gc_free (&gc);
}
