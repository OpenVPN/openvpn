/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
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

#include "options_util.h"

const char *
parse_auth_failed_temp(struct options *o, const char *reason)
{
    struct gc_arena gc = gc_new();

    const char *message = reason;
    char *m = string_alloc(reason, &gc);

    /* Check if the message uses the TEMP[flags]: message format*/
    char *endofflags = strstr(m, "]");

    /* Temporary failure from the server */
    if (m[0] == '[' && endofflags)
    {
        message = strstr(reason, "]") + 1;
        /* null terminate the substring to only looks for flags between [ and ] */
        *endofflags = '\x00';
        const char *token = strtok(m, "[,");
        while (token)
        {
            if (!strncmp(token, "backoff ", strlen("backoff ")))
            {
                if (sscanf(token, "backoff %d", &o->server_backoff_time) != 1)
                {
                    msg(D_PUSH, "invalid AUTH_FAIL,TEMP flag: %s", token);
                    o->server_backoff_time = 0;
                }
            }
            else if (!strncmp(token, "advance ", strlen("advance ")))
            {
                token += strlen("advance ");
                if (!strcmp(token, "no"))
                {
                    o->no_advance = true;
                }
                else if (!strcmp(token, "remote"))
                {
                    o->advance_next_remote = true;
                    o->no_advance = false;
                }
                else if (!strcmp(token, "addr"))
                {
                    /* Go on to the next remote */
                    o->no_advance = false;
                }
            }
            else
            {
                msg(D_PUSH_ERRORS, "WARNING: unknown AUTH_FAIL,TEMP flag: %s", token);
            }
            token = strtok(NULL, "[,");
        }
    }

    /* Look for the message in the original buffer to safely be
     * able to return it */
    if (!message || message[0] != ':')
    {
        message = "";
    }
    else
    {
        /* Skip the : at the beginning */
        message += 1;
    }
    gc_free(&gc);
    return message;
}
