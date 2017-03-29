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
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#ifndef HAVE_INET_NTOP

#include "compat.h"

#ifdef _WIN32

#include <windows.h>

/*
 * inet_ntop() and inet_pton() wrap-implementations using
 * WSAAddressToString() and WSAStringToAddress() functions
 *
 * this is needed as long as we support running OpenVPN on WinXP
 */

const char *
inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
    struct sockaddr_storage ss;
    unsigned long s = size;

    ZeroMemory(&ss, sizeof(ss));
    ss.ss_family = af;

    switch (af)
    {
        case AF_INET:
            ((struct sockaddr_in *)&ss)->sin_addr = *(struct in_addr *)src;
            break;

        case AF_INET6:
            ((struct sockaddr_in6 *)&ss)->sin6_addr = *(struct in6_addr *)src;
            break;

        default:
            return NULL;
    }
    /* cannot direclty use &size because of strict aliasing rules */
    return (WSAAddressToString((struct sockaddr *)&ss, sizeof(ss), NULL, dst, &s) == 0) ?
           dst : NULL;
}

#else  /* ifdef _WIN32 */

#error no emulation for inet_ntop

#endif /* ifdef _WIN32 */

#endif /* ifndef HAVE_INET_NTOP */
