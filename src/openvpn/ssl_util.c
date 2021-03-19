/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2020 OpenVPN Inc <sales@openvpn.net>
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

#include "syshead.h"

#include "ssl_util.h"

char *
extract_var_peer_info(const char *peer_info, const char *var,
                      struct gc_arena *gc)
{
    if (!peer_info)
    {
        return NULL;
    }

    const char *var_start = strstr(peer_info, var);
    if (!var_start)
    {
        /* variable not found in peer info */
        return NULL;
    }

    var_start += strlen(var);
    const char *var_end = strstr(var_start, "\n");
    if (!var_end)
    {
        /* var is at end of the peer_info list and no '\n' follows */
        var_end = var_start + strlen(var_start);
    }

    char *var_value = string_alloc(var_start, gc);
    /* NULL terminate the copy at the right position */
    var_value[var_end - var_start] = '\0';
    return var_value;
}

unsigned int
extract_iv_proto(const char *peer_info)
{
    const char *optstr = peer_info ? strstr(peer_info, "IV_PROTO=") : NULL;
    if (optstr)
    {
        int proto = 0;
        int r = sscanf(optstr, "IV_PROTO=%d", &proto);
        if (r == 1 && proto > 0)
        {
            return proto;
        }
    }
    return 0;
}
