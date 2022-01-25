/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2014-2015 David Sommerseth <davids@redhat.com>
 *  Copyright (C) 2016-2022 David Sommerseth <davids@openvpn.net>
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
#include "console.h"
#include "error.h"
#include "buffer.h"
#include "misc.h"

#ifdef ENABLE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif


struct _query_user query_user[QUERY_USER_NUMSLOTS];  /* GLOBAL */


void
query_user_clear(void)
{
    int i;

    for (i = 0; i < QUERY_USER_NUMSLOTS; i++)
    {
        CLEAR(query_user[i]);
    }
}


void
query_user_add(char *prompt, size_t prompt_len,
               char *resp, size_t resp_len,
               bool echo)
{
    int i;

    /* Ensure input is sane.  All these must be present otherwise it is
     * a programming error.
     */
    ASSERT( prompt_len > 0 && prompt != NULL && resp_len > 0 && resp != NULL );

    /* Seek to the last unused slot */
    for (i = 0; i < QUERY_USER_NUMSLOTS; i++)
    {
        if (query_user[i].prompt == NULL)
        {
            break;
        }
    }
    ASSERT( i < QUERY_USER_NUMSLOTS );  /* Unlikely, but we want to panic if it happens */

    /* Save the information needed for the user interaction */
    query_user[i].prompt = prompt;
    query_user[i].prompt_len = prompt_len;
    query_user[i].response = resp;
    query_user[i].response_len = resp_len;
    query_user[i].echo = echo;
}
