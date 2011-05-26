/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
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

#ifndef SYSHEAD_H
#define SYSHEAD_H

/*
 * Only include if not during configure
 */
#ifndef PACKAGE_NAME
#include "config.h"
#endif

/* branch prediction hints */
#if defined(__GNUC__)
# define likely(x)       __builtin_expect((x),1)
# define unlikely(x)     __builtin_expect((x),0)
#else
# define likely(x)      (x)
# define unlikely(x)    (x)
#endif

#if defined(_WIN32) && !defined(WIN32)
#define WIN32
#endif

#ifdef WIN32
#include <windows.h>
#include <winsock2.h>
#define sleep(x) Sleep((x)*1000)
#define random rand
#define srandom srand
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#ifndef WIN32
#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif
#endif

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_SYS_SOCKET_H
# if defined(TARGET_LINUX) && !defined(_GNU_SOURCE)
   /* needed for peercred support on glibc-2.8 */
#  define _GNU_SOURCE
# endif
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_ERR_H
#include <err.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#ifdef USE_LIBDL
#include <dlfcn.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif

#ifdef HAVE_SYS_EPOLL_H
#include <sys/epoll.h>
#endif

#ifdef HAVE_SETCON
#include <selinux/selinux.h>
#endif

#ifdef TARGET_SOLARIS
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#else
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef TARGET_LINUX

#if defined(HAVE_NETINET_IF_ETHER_H)
#include <netinet/if_ether.h>
#endif

#ifdef HAVE_LINUX_IF_TUN_H
#include <linux/if_tun.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif

#ifdef HAVE_LINUX_TYPES_H
#include <linux/types.h>
#endif

#ifdef HAVE_LINUX_ERRQUEUE_H
#include <linux/errqueue.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#endif /* TARGET_LINUX */

#ifdef TARGET_SOLARIS

#ifdef HAVE_STROPTS_H
#include <stropts.h>
#undef S_ERROR
#endif

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#endif /* TARGET_SOLARIS */

#ifdef TARGET_OPENBSD

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

#endif /* TARGET_OPENBSD */

#ifdef TARGET_FREEBSD

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

#endif /* TARGET_FREEBSD */

#ifdef TARGET_NETBSD

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#endif /* TARGET_NETBSD */

#ifdef TARGET_DRAGONFLY

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NET_TUN_IF_TUN_H
#include <net/tun/if_tun.h>
#endif

#endif /* TARGET_DRAGONFLY */

#ifdef WIN32
#include <iphlpapi.h>
#include <wininet.h>
#endif

#ifdef HAVE_SYS_MMAN_H
#ifdef TARGET_DARWIN
#define _P1003_1B_VISIBLE
#endif /* TARGET_DARWIN */
#include <sys/mman.h>
#endif

/*
 * Pedantic mode is meant to accomplish lint-style program checking,
 * not to build a working executable.
 */
#ifdef __STRICT_ANSI__
# define PEDANTIC 1
# undef HAVE_CPP_VARARG_MACRO_GCC
# undef HAVE_CPP_VARARG_MACRO_ISO
# undef EMPTY_ARRAY_SIZE
# define EMPTY_ARRAY_SIZE 1
# undef inline
# define inline
#else
# define PEDANTIC 0
#endif

/*
 * Do we have the capability to support the --passtos option?
 */
#if defined(IPPROTO_IP) && defined(IP_TOS) && defined(HAVE_SETSOCKOPT)
#define PASSTOS_CAPABILITY 1
#else
#define PASSTOS_CAPABILITY 0
#endif

/*
 * Do we have the capability to report extended socket errors?
 */
#if defined(HAVE_LINUX_TYPES_H) && defined(HAVE_LINUX_ERRQUEUE_H) && defined(HAVE_SOCK_EXTENDED_ERR) && defined(HAVE_MSGHDR) && defined(HAVE_CMSGHDR) && defined(CMSG_FIRSTHDR) && defined(CMSG_NXTHDR) && defined(IP_RECVERR) && defined(MSG_ERRQUEUE) && defined(SOL_IP) && defined(HAVE_IOVEC)
#define EXTENDED_SOCKET_ERROR_CAPABILITY 1
#else
#define EXTENDED_SOCKET_ERROR_CAPABILITY 0
#endif

/*
 * Does this platform support linux-style IP_PKTINFO?
 */
#if defined(ENABLE_MULTIHOME) && defined(HAVE_IN_PKTINFO) && defined(IP_PKTINFO) && defined(HAVE_MSGHDR) && defined(HAVE_CMSGHDR) && defined(HAVE_IOVEC) && defined(CMSG_FIRSTHDR) && defined(CMSG_NXTHDR) && defined(HAVE_RECVMSG) && defined(HAVE_SENDMSG)
#define ENABLE_IP_PKTINFO 1
#else
#define ENABLE_IP_PKTINFO 0
#endif

/*
 * Disable ESEC
 */
#if 0
#undef EXTENDED_SOCKET_ERROR_CAPABILITY
#define EXTENDED_SOCKET_ERROR_CAPABILITY 0
#endif

/*
 * Do we have a syslog capability?
 */
#if defined(HAVE_OPENLOG) && defined(HAVE_SYSLOG)
#define SYSLOG_CAPABILITY 1
#else
#define SYSLOG_CAPABILITY 0
#endif

/*
 * Does this OS draw a distinction between binary and ascii files?
 */
#ifndef O_BINARY
#define O_BINARY 0
#endif

/*
 * Directory separation char
 */
#ifdef WIN32
#define OS_SPECIFIC_DIRSEP '\\'
#else
#define OS_SPECIFIC_DIRSEP '/'
#endif

/*
 * Define a boolean value based
 * on Win32 status.
 */
#ifdef WIN32
#define WIN32_0_1 1
#else
#define WIN32_0_1 0
#endif

/*
 * Our socket descriptor type.
 */
#ifdef WIN32
#define SOCKET_UNDEFINED (INVALID_SOCKET)
typedef SOCKET socket_descriptor_t;
#else
#define SOCKET_UNDEFINED (-1)
typedef int socket_descriptor_t;
#endif

static inline int
socket_defined (const socket_descriptor_t sd)
{
  return sd != SOCKET_UNDEFINED;
}

/*
 * Should statistics counters be 64 bits?
 */
#define USE_64_BIT_COUNTERS

/*
 * Should we enable the use of execve() for calling subprocesses,
 * instead of system()?
 */
#if defined(HAVE_EXECVE) && defined(HAVE_FORK)
#define ENABLE_EXECVE
#endif

/*
 * Do we have point-to-multipoint capability?
 */

#if defined(ENABLE_CLIENT_SERVER) && defined(USE_CRYPTO) && defined(USE_SSL) && defined(HAVE_GETTIMEOFDAY)
#define P2MP 1
#else
#define P2MP 0
#endif

#if P2MP && !defined(ENABLE_CLIENT_ONLY)
#define P2MP_SERVER 1
#else
#define P2MP_SERVER 0
#endif

/*
 * HTTPS port sharing capability
 */
#if defined(ENABLE_PORT_SHARE) && P2MP_SERVER && defined(SCM_RIGHTS) && defined(HAVE_MSGHDR) && defined(HAVE_CMSGHDR) && defined(HAVE_IOVEC) && defined(CMSG_FIRSTHDR) && defined(CMSG_NXTHDR) && defined(HAVE_RECVMSG) && defined(HAVE_SENDMSG)
#define PORT_SHARE 1
#else
#define PORT_SHARE 0
#endif

/*
 * Do we have a plug-in capability?
 */
#if defined(USE_LIBDL) || defined(USE_LOAD_LIBRARY)
#define ENABLE_PLUGIN
#endif

/*
 * Enable deferred authentication?
 */
#if defined(CONFIGURE_DEF_AUTH) && P2MP_SERVER && defined(ENABLE_PLUGIN)
#define PLUGIN_DEF_AUTH
#endif
#if defined(CONFIGURE_DEF_AUTH) && P2MP_SERVER && defined(ENABLE_MANAGEMENT)
#define MANAGEMENT_DEF_AUTH
#endif
#if defined(PLUGIN_DEF_AUTH) || defined(MANAGEMENT_DEF_AUTH)
#define ENABLE_DEF_AUTH
#endif

/*
 * Enable packet filter?
 */
#if defined(CONFIGURE_PF) && P2MP_SERVER && defined(ENABLE_PLUGIN) && defined(HAVE_STAT)
#define PLUGIN_PF
#endif
#if defined(CONFIGURE_PF) && P2MP_SERVER && defined(MANAGEMENT_DEF_AUTH)
#define MANAGEMENT_PF
#endif
#if defined(PLUGIN_PF) || defined(MANAGEMENT_PF)
#define ENABLE_PF
#endif

/*
 * Do we support Unix domain sockets?
 */
#if defined(PF_UNIX) && !defined(WIN32)
#define UNIX_SOCK_SUPPORT 1
#else
#define UNIX_SOCK_SUPPORT 0
#endif

/*
 * Compile the struct buffer_list code
 */
#define ENABLE_BUFFER_LIST

/*
 * Should we include OCC (options consistency check) code?
 */
#ifndef ENABLE_SMALL
#define ENABLE_OCC
#endif

/*
 * Should we include NTLM proxy functionality
 */
#if defined(USE_CRYPTO) && defined(ENABLE_HTTP_PROXY)
#define NTLM 1
#else
#define NTLM 0
#endif

/*
 * Should we include proxy digest auth functionality
 */
#if defined(USE_CRYPTO) && defined(ENABLE_HTTP_PROXY)
#define PROXY_DIGEST_AUTH 1
#else
#define PROXY_DIGEST_AUTH 0
#endif

/*
 * Should we include code common to all proxy methods?
 */
#if defined(ENABLE_HTTP_PROXY) || defined(ENABLE_SOCKS)
#define GENERAL_PROXY_SUPPORT
#endif

/*
 * Do we have PKCS11 capability?
 */
#if defined(USE_PKCS11) && defined(USE_CRYPTO) && defined(USE_SSL)
#define ENABLE_PKCS11
#endif

/*
 * Is poll available on this platform?
 */
#if defined(HAVE_POLL) && defined(HAVE_SYS_POLL_H)
#define POLL 1
#else
#define POLL 0
#endif

/*
 * Is epoll available on this platform?
 */
#if defined(HAVE_EPOLL_CREATE) && defined(HAVE_SYS_EPOLL_H)
#define EPOLL 1
#else
#define EPOLL 0
#endif

/* Disable EPOLL */
#if 0
#undef EPOLL
#define EPOLL 0
#endif

/*
 * Should we allow ca/cert/key files to be
 * included inline, in the configuration file?
 */
#define ENABLE_INLINE_FILES 1

/*
 * Support "connection" directive
 */
#if ENABLE_INLINE_FILES
#define ENABLE_CONNECTION 1
#endif

/*
 * Should we include http proxy fallback functionality
 */
#if defined(ENABLE_CONNECTION) && defined(ENABLE_MANAGEMENT) && defined(ENABLE_HTTP_PROXY)
#define HTTP_PROXY_FALLBACK 1
#else
#define HTTP_PROXY_FALLBACK 0
#endif

/*
 * Reduce sensitivity to system clock instability
 * and backtracks.
 */
#define TIME_BACKTRACK_PROTECTION 1

/*
 * Is non-blocking connect() supported?
 */
#if defined(HAVE_GETSOCKOPT) && defined(SOL_SOCKET) && defined(SO_ERROR) && defined(EINPROGRESS) && defined(ETIMEDOUT)
#define CONNECT_NONBLOCK
#endif

/*
 * Do we have the capability to support the AUTO_USERID feature? 
 */
#if defined(ENABLE_AUTO_USERID)
#define AUTO_USERID 1
#else
#define AUTO_USERID 0
#endif

/*
 * Do we support challenge/response authentication, as a console-based client?
 */
#define ENABLE_CLIENT_CR

/*
 * Do we support pushing peer info?
 */
#if defined(USE_CRYPTO) && defined(USE_SSL)
#define ENABLE_PUSH_PEER_INFO
#endif

#endif
