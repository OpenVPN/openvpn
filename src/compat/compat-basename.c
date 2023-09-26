/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2011 - David Sommerseth <davids@redhat.com>
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
#endif

#ifndef HAVE_BASENAME

#include "compat.h"
#include <string.h>

/* Modified version based on glibc-2.14.1 by Roland McGrath <roland@gnu.org>
 * This version is extended to handle both / and \ in path names
 */
char *
basename(char *filename)
{
    char *p = strrchr(filename, '/');
    if (!p)
    {
        /* If NULL, check for \ instead ... might be Windows a path */
        p = strrchr(filename, '\\');
    }
    return p ? p + 1 : (char *) filename;
}

#endif /* HAVE_BASENAME */
