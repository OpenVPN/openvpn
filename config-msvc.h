#include <config-msvc-version.h>

#define CONFIGURE_DEFINES "N/A"

#define ENABLE_PF 1
#define ENABLE_CRYPTO_OPENSSL 1
#define ENABLE_FRAGMENT 1
#define ENABLE_HTTP_PROXY 1
#define ENABLE_LZO 1
#define ENABLE_LZ4 1
#define ENABLE_MANAGEMENT 1
#define ENABLE_PKCS11 1
#define ENABLE_PLUGIN 1
#define ENABLE_PORT_SHARE 1
#define ENABLE_SOCKS 1

#define HAVE_FCNTL_H 1
#define HAVE_STDIO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRERROR 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_LIMITS_H 1
#define HAVE_SYSTEM 1
#define HAVE_TIME 1
#define HAVE_TIME_H 1
#define HAVE_WINDOWS_H 1
#define HAVE_WINSOCK2_H 1
#define HAVE_WS2TCPIP_H 1
#define HAVE_IO_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_LZO_LZO1X_H 1
#define HAVE_LZO_LZOUTIL_H 1
#define HAVE_VERSIONHELPERS_H 1

#define HAVE_ACCESS 1
#define HAVE_CHDIR 1
#define HAVE_CHSIZE 1
#define HAVE_IN_PKTINFO 1

#define HAVE_OPENSSL_ENGINE 1

#define HAVE_DIINSTALLDEVICE 1

#ifndef __cplusplus
#define inline __inline
#endif

#define TARGET_WIN32 1
#define TARGET_ALIAS "Windows-MSVC"

#define HAVE_DECL_SO_MARK 0

#define strncasecmp strnicmp
#define strcasecmp _stricmp

#if _MSC_VER<1900
#define snprintf _snprintf
#endif

#if _MSC_VER < 1800
#define strtoull strtoul
#endif

#define in_addr_t uint32_t
#define ssize_t SSIZE_T

#define S_IRUSR _S_IREAD
#define S_IWUSR _S_IWRITE
#define S_IRGRP (S_IRUSR >> 3)
#define R_OK 4
#define W_OK 2
#define X_OK 1
#define F_OK 0

#define SIGHUP    1
#define SIGINT    2
#define SIGUSR1   10
#define SIGUSR2   12
#define SIGTERM   15

#include <inttypes.h>
typedef uint16_t in_port_t;

#ifdef HAVE_CONFIG_MSVC_LOCAL_H
#include <config-msvc-local.h>
#endif
