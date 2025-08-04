/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
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

/*
 * This plugin is similar to simple.c, except it also logs extra information
 * to stdout for every plugin method called by OpenVPN.
 *
 * See the README file for build instructions.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "openvpn-plugin.h"

/*
 * Our context, where we keep our state.
 */
struct plugin_context {
    const char *username;
    const char *password;
};

/*
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 */
static const char *
get_env(const char *name, const char *envp[])
{
    if (envp)
    {
        const size_t namelen = strlen(name);
        for (int i = 0; envp[i]; ++i)
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

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v1(unsigned int *type_mask, const char *argv[], const char *envp[])
{
    struct plugin_context *context;

    /*
     * Allocate our context
     */
    context = (struct plugin_context *) calloc(1, sizeof(struct plugin_context));
    if (context == NULL)
    {
        printf("PLUGIN: allocating memory for context failed\n");
        return NULL;
    }

    /*
     * Set the username/password we will require.
     */
    context->username = "foo";
    context->password = "bar";

    /*
     * Which callbacks to intercept.
     */
    *type_mask =
        OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_UP)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_DOWN)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_ROUTE_UP)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_IPCHANGE)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_TLS_VERIFY)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_CONNECT_V2)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_DISCONNECT)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_LEARN_ADDRESS)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_TLS_FINAL);

    return (openvpn_plugin_handle_t) context;
}

void
show(const int type, const char *argv[], const char *envp[])
{
    size_t i;
    switch (type)
    {
        case OPENVPN_PLUGIN_UP:
            printf("OPENVPN_PLUGIN_UP\n");
            break;

        case OPENVPN_PLUGIN_DOWN:
            printf("OPENVPN_PLUGIN_DOWN\n");
            break;

        case OPENVPN_PLUGIN_ROUTE_UP:
            printf("OPENVPN_PLUGIN_ROUTE_UP\n");
            break;

        case OPENVPN_PLUGIN_IPCHANGE:
            printf("OPENVPN_PLUGIN_IPCHANGE\n");
            break;

        case OPENVPN_PLUGIN_TLS_VERIFY:
            printf("OPENVPN_PLUGIN_TLS_VERIFY\n");
            break;

        case OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY:
            printf("OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY\n");
            break;

        case OPENVPN_PLUGIN_CLIENT_CONNECT_V2:
            printf("OPENVPN_PLUGIN_CLIENT_CONNECT_V2\n");
            break;

        case OPENVPN_PLUGIN_CLIENT_DISCONNECT:
            printf("OPENVPN_PLUGIN_CLIENT_DISCONNECT\n");
            break;

        case OPENVPN_PLUGIN_LEARN_ADDRESS:
            printf("OPENVPN_PLUGIN_LEARN_ADDRESS\n");
            break;

        case OPENVPN_PLUGIN_TLS_FINAL:
            printf("OPENVPN_PLUGIN_TLS_FINAL\n");
            break;

        default:
            printf("OPENVPN_PLUGIN_?\n");
            break;
    }

    printf("ARGV\n");
    for (i = 0; argv[i] != NULL; ++i)
    {
        printf("%d '%s'\n", (int)i, argv[i]);
    }

    printf("ENVP\n");
    for (i = 0; envp[i] != NULL; ++i)
    {
        printf("%d '%s'\n", (int)i, envp[i]);
    }
}

OPENVPN_EXPORT int
openvpn_plugin_func_v1(openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[])
{
    struct plugin_context *context = (struct plugin_context *) handle;

    show(type, argv, envp);

    /* check entered username/password against what we require */
    if (type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
    {
        /* get username/password from envp string array */
        const char *username = get_env("username", envp);
        const char *password = get_env("password", envp);

        if (username && !strcmp(username, context->username)
            && password && !strcmp(password, context->password))
        {
            return OPENVPN_PLUGIN_FUNC_SUCCESS;
        }
        else
        {
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    }
    else
    {
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct plugin_context *context = (struct plugin_context *) handle;
    free(context);
}
