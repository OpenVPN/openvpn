/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_STRLCPY
#include <string.h>

size_t
strlcpy(char *dest, const char *src, size_t maxlen)
{
    if (maxlen > 0)
    {
        strncpy(dest, src, maxlen - 1);
        dest[maxlen - 1] = 0;
    }
    return strlen(src);
}

size_t
strlcat(char *dest, const char *src, size_t maxlen)
{
    size_t dest_len = strnlen(dest, maxlen);
    if (maxlen > dest_len)
    {
        strncat(dest, src, maxlen - dest_len - 1);
    }
    return dest_len + strlen(src);
}

#endif /* ifndef HAVE_STRLCPY */
