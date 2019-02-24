/*
 *  error -- OpenVPN compatible error reporting API
 *           https://community.openvpn.net/openvpn/wiki/Tapctl
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2018 Simon Rozman <simon@rozman.si>
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

#ifndef ERROR_H
#define ERROR_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

/*
 * These globals should not be accessed directly,
 * but rather through macros or inline functions defined below.
 */
extern unsigned int x_debug_level;
extern int x_msg_line_num;

/* msg() flags */

#define M_DEBUG_LEVEL     (0x0F)         /* debug level mask */

#define M_FATAL           (1<<4)         /* exit program */
#define M_NONFATAL        (1<<5)         /* non-fatal error */
#define M_WARN            (1<<6)         /* call syslog with LOG_WARNING */
#define M_DEBUG           (1<<7)

#define M_ERRNO           (1<<8)         /* show errno description */

#define M_NOMUTE          (1<<11)        /* don't do mute processing */
#define M_NOPREFIX        (1<<12)        /* don't show date/time prefix */
#define M_USAGE_SMALL     (1<<13)        /* fatal options error, call usage_small */
#define M_MSG_VIRT_OUT    (1<<14)        /* output message through msg_status_output callback */
#define M_OPTERR          (1<<15)        /* print "Options error:" prefix */
#define M_NOLF            (1<<16)        /* don't print new line */
#define M_NOIPREFIX       (1<<17)        /* don't print instance prefix */

/* flag combinations which are frequently used */
#define M_ERR     (M_FATAL | M_ERRNO)
#define M_USAGE   (M_USAGE_SMALL | M_NOPREFIX | M_OPTERR)
#define M_CLIENT  (M_MSG_VIRT_OUT | M_NOMUTE | M_NOIPREFIX)


/** Check muting filter */
bool dont_mute(unsigned int flags);

/* Macro to ensure (and teach static analysis tools) we exit on fatal errors */
#ifdef _MSC_VER
#pragma warning(disable: 4127) /* EXIT_FATAL(flags) macro raises "warning C4127: conditional expression is constant" on each non M_FATAL invocation. */
#endif
#define EXIT_FATAL(flags) do { if ((flags) & M_FATAL) {_exit(1);}} while (false)

#define HAVE_VARARG_MACROS
#define msg(flags, ...) do { if (msg_test(flags)) {x_msg((flags), __VA_ARGS__);} EXIT_FATAL(flags); } while (false)
#ifdef ENABLE_DEBUG
#define dmsg(flags, ...) do { if (msg_test(flags)) {x_msg((flags), __VA_ARGS__);} EXIT_FATAL(flags); } while (false)
#else
#define dmsg(flags, ...)
#endif

void x_msg(const unsigned int flags, const char *format, ...);     /* should be called via msg above */

void x_msg_va(const unsigned int flags, const char *format, va_list arglist);

/* Inline functions */

static inline bool
check_debug_level(unsigned int level)
{
    return (level & M_DEBUG_LEVEL) <= x_debug_level;
}

/** Return true if flags represent and enabled, not muted log level */
static inline bool
msg_test(unsigned int flags)
{
    return check_debug_level(flags) && dont_mute(flags);
}

#endif /* ifndef ERROR_H */
