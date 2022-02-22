/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
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

#ifndef SYSHEAD_H
#define SYSHEAD_H

#include "compat.h"
#include <stdbool.h>

/* branch prediction hints */
#if defined(__GNUC__)
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#else
#define likely(x)      (x)
#define unlikely(x)    (x)
#endif

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <tlhelp32.h>
#define sleep(x) Sleep((x)*1000)
#define random rand
#define srandom srand
#endif

#ifdef _MSC_VER /* Visual Studio */
#define __func__ __FUNCTION__
#define __attribute__(x)
#include <inttypes.h>
#endif

#if defined(__APPLE__)
#if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 1070
#define __APPLE_USE_RFC_3542  1
#endif
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifndef _WIN32
#ifndef WEXITSTATUS
#define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
#define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
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

#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif

#ifdef HAVE_IO_H
#include <io.h>
#endif

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#elif defined(HAVE_STDINT_H)
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

#ifdef HAVE_LIMITS_H
#include <limits.h>
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

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_SYS_EPOLL_H
#include <sys/epoll.h>
#endif

#ifdef ENABLE_SELINUX
#include <selinux/selinux.h>
#endif

#if defined(HAVE_LIBGEN_H)
#include <libgen.h>
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

#ifdef TARGET_NETBSD
#include <net/if_tap.h>
#endif

#if defined(TARGET_LINUX) || defined (TARGET_ANDROID)

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

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
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

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
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

#ifdef TARGET_DARWIN

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#endif /* TARGET_DARWIN */

#ifdef _WIN32
/* Missing declarations for MinGW 32. */
/* #if !defined(__MINGW64_VERSION_MAJOR) || __MINGW64_VERSION_MAJOR < 2 */
typedef int MIB_TCP_STATE;
/* #endif */
#include <naptypes.h>
#include <ntddndis.h>
#include <iphlpapi.h>
#include <wininet.h>
#include <shellapi.h>
/* The following two headers are needed of PF_INET6 */
#include <winsock2.h>
#include <ws2tcpip.h>
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
#ifdef PEDANTIC
#undef HAVE_CPP_VARARG_MACRO_GCC
#undef HAVE_CPP_VARARG_MACRO_ISO
#undef EMPTY_ARRAY_SIZE
#define EMPTY_ARRAY_SIZE 1
#undef inline
#define inline
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
 * Do we have nanoseconds gettimeofday?
 */
#if defined(HAVE_GETTIMEOFDAY) || defined(_WIN32)
#define HAVE_GETTIMEOFDAY_NANOSECONDS 1
#endif

/*
 * Do we have the capability to report extended socket errors?
 */
#if defined(HAVE_LINUX_TYPES_H) && defined(HAVE_LINUX_ERRQUEUE_H)
#define EXTENDED_SOCKET_ERROR_CAPABILITY 1
#else
#define EXTENDED_SOCKET_ERROR_CAPABILITY 0
#endif

/*
 * Does this platform support linux-style IP_PKTINFO
 * or bsd-style IP_RECVDSTADDR ?
 */
#if defined(ENABLE_MULTIHOME) && ((defined(HAVE_IN_PKTINFO) && defined(IP_PKTINFO)) || defined(IP_RECVDSTADDR)) && defined(HAVE_MSGHDR) && defined(HAVE_CMSGHDR) && defined(HAVE_IOVEC) && defined(CMSG_FIRSTHDR) && defined(CMSG_NXTHDR) && defined(HAVE_RECVMSG) && defined(HAVE_SENDMSG)
#define ENABLE_IP_PKTINFO 1
#else
#define ENABLE_IP_PKTINFO 0
#endif

/*
 * Does this platform define SOL_IP
 * or only bsd-style IPPROTO_IP ?
 */
#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

/*
 * Define type sa_family_t if it isn't defined in the socket headers
 */
#ifndef HAVE_SA_FAMILY_T
typedef unsigned short sa_family_t;
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
#ifdef _WIN32
#define OS_SPECIFIC_DIRSEP '\\'
#else
#define OS_SPECIFIC_DIRSEP '/'
#endif

/*
 * Our socket descriptor type.
 */
#ifdef _WIN32
#define SOCKET_UNDEFINED (INVALID_SOCKET)
typedef SOCKET socket_descriptor_t;
#else
#define SOCKET_UNDEFINED (-1)
typedef int socket_descriptor_t;
#endif

static inline int
socket_defined(const socket_descriptor_t sd)
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
#define ENABLE_FEATURE_EXECVE
#endif

/*
 * Do we have point-to-multipoint capability?
 */

#if defined(HAVE_GETTIMEOFDAY_NANOSECONDS)
#define P2MP 1
#else
#define P2MP 0
#endif

/*
 * HTTPS port sharing capability
 */
#if defined(ENABLE_PORT_SHARE) && defined(SCM_RIGHTS) && defined(HAVE_MSGHDR) && defined(HAVE_CMSGHDR) && defined(HAVE_IOVEC) && defined(CMSG_FIRSTHDR) && defined(CMSG_NXTHDR) && defined(HAVE_RECVMSG) && defined(HAVE_SENDMSG)
#define PORT_SHARE 1
#else
#define PORT_SHARE 0
#endif

/*
 * Enable deferred authentication?
 */
#if defined(ENABLE_DEF_AUTH) && defined(ENABLE_PLUGIN)
#define PLUGIN_DEF_AUTH
#endif
#if defined(ENABLE_DEF_AUTH) && defined(ENABLE_MANAGEMENT)
#define MANAGEMENT_DEF_AUTH
#endif
#if !defined(PLUGIN_DEF_AUTH) && !defined(MANAGEMENT_DEF_AUTH)
#undef ENABLE_DEF_AUTH
#endif

#ifdef ENABLE_CRYPTO_MBEDTLS
#define ENABLE_PREDICTION_RESISTANCE
#endif /* ENABLE_CRYPTO_MBEDTLS */

/*
 * Enable packet filter?
 */
#if defined(ENABLE_PF) && defined(ENABLE_PLUGIN) && defined(HAVE_STAT)
#define PLUGIN_PF
#endif
#if defined(ENABLE_PF) && defined(MANAGEMENT_DEF_AUTH)
#define MANAGEMENT_PF
#endif
#if !defined(PLUGIN_PF) && !defined(MANAGEMENT_PF)
#undef ENABLE_PF
#endif

/*
 * Do we support Unix domain sockets?
 */
#if defined(PF_UNIX) && !defined(_WIN32)
#define UNIX_SOCK_SUPPORT 1
#else
#define UNIX_SOCK_SUPPORT 0
#endif

/*
 * Should we include NTLM proxy functionality
 */
#define NTLM 1

/*
 * Should we include proxy digest auth functionality
 */
#define PROXY_DIGEST_AUTH 1

/*
 * Do we have CryptoAPI capability?
 */
#if defined(_WIN32) && defined(ENABLE_CRYPTO_OPENSSL)
#define ENABLE_CRYPTOAPI
#endif

/*
 * Is poll available on this platform?
 */
#if defined(HAVE_POLL) && defined(HAVE_POLL_H)
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
 * Reduce sensitivity to system clock instability
 * and backtracks.
 */
#if defined(HAVE_GETTIMEOFDAY_NANOSECONDS)
#define TIME_BACKTRACK_PROTECTION 1
#endif

/*
 * Enable traffic shaper.
 */
#if defined(HAVE_GETTIMEOFDAY_NANOSECONDS)
#define ENABLE_FEATURE_SHAPER 1
#endif

/*
 * Is non-blocking connect() supported?
 */
#if defined(HAVE_GETSOCKOPT) && defined(SOL_SOCKET) && defined(SO_ERROR) && defined(EINPROGRESS) && defined(ETIMEDOUT)
#define CONNECT_NONBLOCK
#endif

/*
 * Compression support
 */
#if defined(ENABLE_LZO) || defined(ENABLE_LZ4)    \
    || defined(ENABLE_COMP_STUB)
#define USE_COMP
#endif

/*
 * Enable --memstats option
 */
#ifdef TARGET_LINUX
#define ENABLE_MEMSTATS
#endif

#endif /* ifndef SYSHEAD_H */
