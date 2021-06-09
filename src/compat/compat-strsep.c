/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2019-2021 Arne Schwabe <arne@rfc2549.org>
 *  Copyright (C) 1992-2019 Free Software Foundation, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#ifndef HAVE_STRSEP
#include <string.h>

/*
 * Modified version based on the glibc
 */
char *
strsep(char **stringp, const char *delim)
{
    char *begin, *end;
    begin = *stringp;
    if (begin == NULL)
    {
        return NULL;
    }
    /* Find the end of the token.  */
    end = begin + strcspn(begin, delim);
    if (*end)
    {
        /* Terminate the token and set *STRINGP past NUL character.  */
        *end++ = '\0';
        *stringp = end;
    }
    else
    {
        /* No more delimiters; this is the last token.  */
        *stringp = NULL;
    }
    return begin;
}
#endif /* ifndef HAVE_STRSEP */
