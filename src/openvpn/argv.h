/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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
    struct gc_arena gc;
    size_t capacity;
    size_t argc;
    char **argv;
};

struct argv argv_new(void);

void argv_free(struct argv *a);

const char *argv_str(const struct argv *a, struct gc_arena *gc, const unsigned int flags);

struct argv argv_insert_head(const struct argv *a, const char *head);

void argv_msg(const int msglev, const struct argv *a);

void argv_msg_prefix(const int msglev, const struct argv *a, const char *prefix);

void argv_parse_cmd(struct argv *a, const char *s);

bool argv_printf(struct argv *a, const char *format, ...)
#ifdef __GNUC__
#if __USE_MINGW_ANSI_STDIO
__attribute__ ((format(gnu_printf, 2, 3)))
#else
__attribute__ ((format(__printf__, 2, 3)))
#endif
#endif
;

bool argv_printf_cat(struct argv *a, const char *format, ...)
#ifdef __GNUC__
#if __USE_MINGW_ANSI_STDIO
__attribute__ ((format(gnu_printf, 2, 3)))
#else
__attribute__ ((format(__printf__, 2, 3)))
#endif
#endif
;

#endif /* ifndef ARGV_H */
