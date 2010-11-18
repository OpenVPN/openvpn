/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

#ifndef ERROR_H
#define ERROR_H

#include "basic.h"

/* #define ABORT_ON_ERROR */

#ifdef ENABLE_PKCS11
#define ERR_BUF_SIZE 8192
#else
#define ERR_BUF_SIZE 1280
#endif

struct gc_arena;

/*
 * Where should messages be printed before syslog is opened?
 * Not used if OPENVPN_DEBUG_COMMAND_LINE is defined.
 */
#define OPENVPN_MSG_FP   stdout
#define OPENVPN_ERROR_FP stderr

/*
 * Exit status codes
 */

#define OPENVPN_EXIT_STATUS_GOOD                    0
#define OPENVPN_EXIT_STATUS_ERROR                   1
#define OPENVPN_EXIT_STATUS_USAGE                   1
#define OPENVPN_EXIT_STATUS_CANNOT_OPEN_DEBUG_FILE  1

/*
 * Special command line debugging mode.
 * If OPENVPN_DEBUG_COMMAND_LINE
 * is defined, contents of argc/argv will
 * be dumped to OPENVPN_DEBUG_FILE as well
 * as all other OpenVPN messages.
 */

/* #define OPENVPN_DEBUG_COMMAND_LINE */
#define OPENVPN_DEBUG_FILE PACKAGE ".log"

/* String and Error functions */

#ifdef WIN32
# define openvpn_errno()             GetLastError()
# define openvpn_errno_socket()      WSAGetLastError()
# define openvpn_strerror(e, gc)     strerror_win32(e, gc)
  const char *strerror_win32 (DWORD errnum, struct gc_arena *gc);
#else
# define openvpn_errno()             errno
# define openvpn_errno_socket()      errno
# define openvpn_strerror(x, gc)     strerror(x)
#endif

/*
 * These globals should not be accessed directly,
 * but rather through macros or inline functions defined below.
 */
extern unsigned int x_debug_level;
extern int x_msg_line_num;

/* msg() flags */

#define M_DEBUG_LEVEL     (0x0F)	 /* debug level mask */

#define M_FATAL           (1<<4)	 /* exit program */
#define M_NONFATAL        (1<<5)	 /* non-fatal error */
#define M_WARN	          (1<<6)	 /* call syslog with LOG_WARNING */
#define M_DEBUG           (1<<7)

#define M_ERRNO           (1<<8)	 /* show errno description */
#define M_ERRNO_SOCK      (1<<9)	 /* show socket errno description */
#define M_SSL             (1<<10)	 /* show SSL error */
#define M_NOMUTE          (1<<11)        /* don't do mute processing */
#define M_NOPREFIX        (1<<12)        /* don't show date/time prefix */
#define M_USAGE_SMALL     (1<<13)        /* fatal options error, call usage_small */
#define M_MSG_VIRT_OUT    (1<<14)        /* output message through msg_status_output callback */
#define M_OPTERR          (1<<15)        /* print "Options error:" prefix */
#define M_NOLF            (1<<16)        /* don't print new line */
#define M_NOIPREFIX       (1<<17)        /* don't print instance prefix */

/* flag combinations which are frequently used */
#define M_ERR     (M_FATAL | M_ERRNO)
#define M_SOCKERR (M_FATAL | M_ERRNO_SOCK)
#define M_SSLERR  (M_FATAL | M_SSL)
#define M_USAGE   (M_USAGE_SMALL | M_NOPREFIX | M_OPTERR)
#define M_CLIENT  (M_MSG_VIRT_OUT | M_NOMUTE | M_NOIPREFIX)

/*
 * Mute levels are designed to avoid large numbers of
 * mostly similar messages clogging the log file.
 *
 * A mute level of 0 is always printed.
 */
#define MUTE_LEVEL_SHIFT 24
#define MUTE_LEVEL_MASK 0xFF

#define ENCODE_MUTE_LEVEL(mute_level) (((mute_level) & MUTE_LEVEL_MASK) << MUTE_LEVEL_SHIFT)
#define DECODE_MUTE_LEVEL(flags) (((flags) >> MUTE_LEVEL_SHIFT) & MUTE_LEVEL_MASK)

/*
 * log_level:  verbosity level n (--verb n) must be >= log_level to print.
 * mute_level: don't print more than n (--mute n) consecutive messages at
 *             a given mute level, or if 0 disable muting and print everything.
 *
 * Mask map:
 * Bits 0-3:   log level
 * Bits 4-23:  M_x flags
 * Bits 24-31: mute level
 */
#define LOGLEV(log_level, mute_level, other) ((log_level) | ENCODE_MUTE_LEVEL(mute_level) | other)

/*
 * If compiler supports variable arguments in macros, define
 * msg() as a macro for optimization win.
 */

bool dont_mute (unsigned int flags); /* check muting filter */

#define MSG_TEST(flags) (unlikely((((unsigned int)flags) & M_DEBUG_LEVEL) <= x_debug_level) && dont_mute (flags))

#if defined(HAVE_CPP_VARARG_MACRO_ISO) && !defined(__LCLINT__)
# define HAVE_VARARG_MACROS
# define msg(flags, ...) do { if (MSG_TEST(flags)) x_msg((flags), __VA_ARGS__); } while (false)
# ifdef ENABLE_DEBUG
#  define dmsg(flags, ...) do { if (MSG_TEST(flags)) x_msg((flags), __VA_ARGS__); } while (false)
# else
#  define dmsg(flags, ...)
# endif
#elif defined(HAVE_CPP_VARARG_MACRO_GCC) && !defined(__LCLINT__)
# define HAVE_VARARG_MACROS
# define msg(flags, args...) do { if (MSG_TEST(flags)) x_msg((flags), args); } while (false)
# ifdef ENABLE_DEBUG
#  define dmsg(flags, args...) do { if (MSG_TEST(flags)) x_msg((flags), args); } while (false)
# else
#  define dmsg(flags, args...)
# endif
#else
# if !PEDANTIC
#  ifdef _MSC_VER
#   pragma message("this compiler appears to lack vararg macros which will cause a significant degradation in efficiency")
#  else
#   warning this compiler appears to lack vararg macros which will cause a significant degradation in efficiency (you can ignore this warning if you are using LCLINT)
#  endif
# endif
# define msg x_msg
# define dmsg x_msg
#endif

void x_msg (const unsigned int flags, const char *format, ...)
#ifdef __GNUC__
    __attribute__ ((format (printf, 2, 3)))
#endif
    ; /* should be called via msg above */

/*
 * Function prototypes
 */

void error_reset (void);

/* route errors to stderr that would normally go to stdout */
void errors_to_stderr (void);

void set_suppress_timestamps (bool suppressed);

#define SDL_CONSTRAIN (1<<0)
bool set_debug_level (const int level, const unsigned int flags);

bool set_mute_cutoff (const int cutoff);

int get_debug_level (void);
int get_mute_cutoff (void);

const char *msg_flags_string (const unsigned int flags, struct gc_arena *gc);

/*
 * File to print messages to before syslog is opened.
 */
FILE *msg_fp(const unsigned int flags);

/* Fatal logic errors */
#define ASSERT(x) do { if (!(x)) assert_failed(__FILE__, __LINE__); } while (false)

void assert_failed (const char *filename, int line);

#ifdef ENABLE_DEBUG
void crash (void); /* force a segfault (debugging only) */
#endif

/* Inline functions */

static inline bool
check_debug_level (unsigned int level)
{
  return (level & M_DEBUG_LEVEL) <= x_debug_level;
}

/* Call if we forked */
void msg_forked (void);

/* syslog output */

void open_syslog (const char *pgmname, bool stdio_to_null);
void close_syslog ();

/* log file output */
void redirect_stdout_stderr (const char *file, bool append);

#ifdef WIN32
/* get original stderr handle, even if redirected by --log/--log-append */
HANDLE get_orig_stderr (void);
#endif

/* exit program */
void openvpn_exit (const int status);

/*
 * Check the return status of read/write routines.
 */

struct link_socket;
struct tuntap;

extern unsigned int x_cs_info_level;
extern unsigned int x_cs_verbose_level;
extern unsigned int x_cs_err_delay_ms;

void reset_check_status (void);
void set_check_status (unsigned int info_level, unsigned int verbose_level);

void x_check_status (int status,
		     const char *description,
		     struct link_socket *sock,
		     struct tuntap *tt);

static inline void
check_status (int status, const char *description, struct link_socket *sock, struct tuntap *tt)
{
  if (status < 0 || check_debug_level (x_cs_verbose_level))
    x_check_status (status, description, sock, tt);
}

static inline void
set_check_status_error_delay (unsigned int milliseconds)
{
  x_cs_err_delay_ms = milliseconds;
}

/*
 * In multiclient mode, put a client-specific prefix
 * before each message.
 *
 * TODO: x_msg_prefix should be thread-local
 */

extern const char *x_msg_prefix;

void msg_thread_init (void);
void msg_thread_uninit (void);

static inline void
msg_set_prefix (const char *prefix)
{
    x_msg_prefix = prefix;
}

static inline const char *
msg_get_prefix (void)
{
    return x_msg_prefix;
}

/*
 * Allow MSG to be redirected through a virtual_output object
 */

struct virtual_output;

extern const struct virtual_output *x_msg_virtual_output;

static inline void
msg_set_virtual_output (const struct virtual_output *vo)
{
  x_msg_virtual_output = vo;
}

static inline const struct virtual_output *
msg_get_virtual_output (void)
{
  return x_msg_virtual_output;
}

/*
 * Return true if this is a system error
 * which can be safely ignored.
 */
static inline bool
ignore_sys_error (const int err)
{
  /* I/O operation pending */
#ifdef WIN32
  if (err == WSAEWOULDBLOCK || err == WSAEINVAL)
    return true;
#else
  if (err == EAGAIN)
    return true;
#endif

#if 0 /* if enabled, suppress ENOBUFS errors */
#ifdef ENOBUFS
  /* No buffer space available */
  if (err == ENOBUFS)
    return true;
#endif
#endif

  return false;
}

#include "errlevel.h"

#endif
