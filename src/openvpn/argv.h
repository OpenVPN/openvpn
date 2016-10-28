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
 *
 *
 *  A printf-like function (that only recognizes a subset of standard printf
 *  format operators) that prints arguments to an argv list instead
 *  of a standard string.  This is used to build up argv arrays for passing
 *  to execve.
 */

#ifndef ARGV_H
#define ARGV_H

#include "buffer.h"

struct argv {
  size_t capacity;
  size_t argc;
  char **argv;
  char *system_str;
};

void argv_init (struct argv *a);
struct argv argv_new (void);
void argv_reset (struct argv *a);
char *argv_term (const char **f);
const char *argv_str (const struct argv *a, struct gc_arena *gc, const unsigned int flags);
struct argv argv_insert_head (const struct argv *a, const char *head);
void argv_msg (const int msglev, const struct argv *a);
void argv_msg_prefix (const int msglev, const struct argv *a, const char *prefix);
const char *argv_system_str (const struct argv *a);

#define APA_CAT (1<<0) /* concatentate onto existing struct argv list */
void argv_printf_arglist (struct argv *a, const char *format, const unsigned int flags, va_list arglist);

void argv_printf (struct argv *a, const char *format, ...)
#ifdef __GNUC__
#if __USE_MINGW_ANSI_STDIO
        __attribute__ ((format (gnu_printf, 2, 3)))
#else
        __attribute__ ((format (__printf__, 2, 3)))
#endif
#endif
  ;

void argv_printf_cat (struct argv *a, const char *format, ...)
#ifdef __GNUC__
#if __USE_MINGW_ANSI_STDIO
        __attribute__ ((format (gnu_printf, 2, 3)))
#else
        __attribute__ ((format (__printf__, 2, 3)))
#endif
#endif
  ;

#endif
