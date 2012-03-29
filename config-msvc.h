#include <config-msvc-version.h>

#define CONFIGURE_DEFINES "N/A"

#define ENABLE_DEF_AUTH 1
#define ENABLE_PF 1
#define ENABLE_CLIENT_SERVER 1
#define ENABLE_CRYPTO 1
#define ENABLE_CRYPTO_OPENSSL 1
#define ENABLE_DEBUG 1
#define ENABLE_EUREPHIA 1
#define ENABLE_FRAGMENT 1
#define ENABLE_HTTP_PROXY 1
#define ENABLE_LZO 1
#define ENABLE_MANAGEMENT 1
#define ENABLE_MULTIHOME 1
#define ENABLE_PKCS11 1
#define ENABLE_PLUGIN 1
#define ENABLE_PORT_SHARE 1
#define ENABLE_SOCKS 1
#define ENABLE_SSL 1

#define HAVE_ERRNO_H 1
#define HAVE_FCNTL_H 1
#define HAVE_CTYPE_H 1
#define HAVE_STDARG_H 1
#define HAVE_STDIO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRDUP 1
#define HAVE_STRERROR 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_LIMITS_H 1
#define HAVE_SYSTEM 1
#define HAVE_TIME 1
#define HAVE_TIME_H 1
#define HAVE_UNLINK 1
#define HAVE_VSNPRINTF 1
#define HAVE_WINDOWS_H 1
#define HAVE_WINSOCK2_H 1
#define HAVE_WS2TCPIP_H 1
#define HAVE_IO_H 1
#define HAVE_DIRECT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_LZO_LZO1X_H 1
#define HAVE_LZO_LZOUTIL_H 1

#define HAVE_ACCESS 1
#define HAVE_CHDIR 1
#define HAVE_CHSIZE 1
#define HAVE_CPP_VARARG_MACRO_ISO 1
#define HAVE_CTIME 1
#define HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH 1
#define HAVE_IN_PKTINFO 1
#define HAVE_MEMSET 1
#define HAVE_PUTENV 1
#define HAVE_STAT 1

#define HAVE_SOCKET 1
#define HAVE_RECV 1
#define HAVE_RECVFROM 1
#define HAVE_SEND 1
#define HAVE_SENDTO 1
#define HAVE_LISTEN 1
#define HAVE_ACCEPT 1
#define HAVE_CONNECT 1
#define HAVE_BIND 1
#define HAVE_SELECT 1
#define HAVE_GETHOSTBYNAME 1
#define HAVE_INET_NTOA 1
#define HAVE_SETSOCKOPT 1
#define HAVE_GETSOCKOPT 1
#define HAVE_GETSOCKNAME 1
#define HAVE_POLL 1

#define HAVE_OPENSSL_ENGINE 1

#ifndef __cplusplus
#define inline __inline
#endif

#define EMPTY_ARRAY_SIZE 0
#define TARGET_WIN32 1
#define TARGET_ALIAS "Windows-MSVC"

#define HAVE_DECL_SO_MARK 0

#define strncasecmp strnicmp
#define strcasecmp _stricmp
#define snprintf _snprintf
#define strtoull strtoul

#define in_addr_t uint32_t
#define ssize_t SSIZE_T

#define S_IRUSR 0
#define S_IWUSR 0
#define R_OK 4
#define W_OK 2
#define X_OK 1
#define F_OK 0

#define SIGHUP    1
#define SIGINT    2
#define SIGUSR1   10
#define SIGUSR2   12
#define SIGTERM   15

typedef unsigned __int64	uint64_t;
typedef unsigned __int32	uint32_t;
typedef unsigned __int16	uint16_t;
typedef unsigned __int8		uint8_t;
typedef __int64		int64_t;
typedef __int32		int32_t;
typedef __int16		int16_t;
typedef __int8		int8_t;

#ifdef HAVE_CONFIG_MSVC_LOCAL_H
#include <config-msvc-local.h>
#endif

