/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
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

/*
 * OpenVPN plugin module to do PAM authentication using a split
 * privilege model.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdint.h>

#include "utils.h"

char *
searchandreplace(const char *tosearch, const char *searchfor, const char *replacewith)
{
    if (!tosearch || !searchfor || !replacewith)
    {
        return NULL;
    }

    size_t tosearchlen = strlen(tosearch);
    size_t replacewithlen = strlen(replacewith);
    size_t templen = tosearchlen * replacewithlen;

    if (tosearchlen == 0 || strlen(searchfor) == 0 || replacewithlen == 0)
    {
        return NULL;
    }

    bool is_potential_integer_overflow =  (templen == SIZE_MAX) || (templen / tosearchlen != replacewithlen);

    if (is_potential_integer_overflow)
    {
        return NULL;
    }

    /* state: all parameters are valid */

    const char *searching = tosearch;
    char *scratch;

    char temp[templen+1];
    temp[0] = 0;

    scratch = strstr(searching,searchfor);
    if (!scratch)
    {
        return strdup(tosearch);
    }

    while (scratch)
    {
        strncat(temp,searching,scratch-searching);
        strcat(temp,replacewith);

        searching = scratch+strlen(searchfor);
        scratch = strstr(searching,searchfor);
    }
    return strdup(temp);
}

const char *
get_env(const char *name, const char *envp[])
{
    if (envp)
    {
        int i;
        const int namelen = strlen(name);
        for (i = 0; envp[i]; ++i)
        {
            if (!strncmp(envp[i], name, namelen))
            {
                const char *cp = envp[i] + namelen;
                if (*cp == '=')
                {
                    return cp + 1;
                }
            }
        }
    }
    return NULL;
}

int
string_array_len(const char *array[])
{
    int i = 0;
    if (array)
    {
        while (array[i])
        {
            ++i;
        }
    }
    return i;
}
