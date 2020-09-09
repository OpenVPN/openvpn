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
 * This file implements a simple OpenVPN plugin module which
 * will test deferred authentication and packet filtering.
 *
 * Will run on Windows or *nix.
 *
 * Sample usage:
 *
 * setenv test_deferred_auth 20
 * setenv test_packet_filter 10
 * plugin plugin/defer/simple.so
 *
 * This will enable deferred authentication to occur 20
 * seconds after the normal TLS authentication process,
 * and will cause a packet filter file to be generated 10
 * seconds after the initial TLS negotiation, using
 * {common-name}.pf as the source.
 *
 * Sample packet filter configuration:
 *
 * [CLIENTS DROP]
 * +otherclient
 * [SUBNETS DROP]
 * +10.0.0.0/8
 * -10.10.0.8
 * [END]
 *
 * See the README file for build instructions.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "openvpn-plugin.h"

/* bool definitions */
#define bool int
#define true 1
#define false 0

/*
 * Our context, where we keep our state.
 */

struct plugin_context {
    int test_deferred_auth;
    int test_packet_filter;
};

struct plugin_per_client_context {
    int n_calls;
    bool generated_pf_file;
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

/* used for safe printf of possible NULL strings */
static const char *
np(const char *str)
{
    if (str)
    {
        return str;
    }
    else
    {
        return "[NULL]";
    }
}

static int
atoi_null0(const char *str)
{
    if (str)
    {
        return atoi(str);
    }
    else
    {
        return 0;
    }
}

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v1(unsigned int *type_mask, const char *argv[], const char *envp[])
{
    struct plugin_context *context;

    printf("FUNC: openvpn_plugin_open_v1\n");

    /*
     * Allocate our context
     */
    context = (struct plugin_context *) calloc(1, sizeof(struct plugin_context));
    if (context == NULL)
    {
        printf("PLUGIN: allocating memory for context failed\n");
        return NULL;
    }

    context->test_deferred_auth = atoi_null0(get_env("test_deferred_auth", envp));
    printf("TEST_DEFERRED_AUTH %d\n", context->test_deferred_auth);

    context->test_packet_filter = atoi_null0(get_env("test_packet_filter", envp));
    printf("TEST_PACKET_FILTER %d\n", context->test_packet_filter);

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
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_TLS_FINAL)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_ENABLE_PF);

    return (openvpn_plugin_handle_t) context;
}

static int
auth_user_pass_verify(struct plugin_context *context, struct plugin_per_client_context *pcc, const char *argv[], const char *envp[])
{
    if (context->test_deferred_auth)
    {
        /* get username/password from envp string array */
        const char *username = get_env("username", envp);
        const char *password = get_env("password", envp);

        /* get auth_control_file filename from envp string array*/
        const char *auth_control_file = get_env("auth_control_file", envp);

        printf("DEFER u='%s' p='%s' acf='%s'\n",
               np(username),
               np(password),
               np(auth_control_file));

        /* Authenticate asynchronously in n seconds */
        if (auth_control_file)
        {
            char buf[256];
            int auth = 2;
            sscanf(username, "%d", &auth);
            snprintf(buf, sizeof(buf), "( sleep %d ; echo AUTH %s %d ; echo %d >%s ) &",
                     context->test_deferred_auth,
                     auth_control_file,
                     auth,
                     pcc->n_calls < auth,
                     auth_control_file);
            printf("%s\n", buf);
            system(buf);
            pcc->n_calls++;
            return OPENVPN_PLUGIN_FUNC_DEFERRED;
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

static int
tls_final(struct plugin_context *context, struct plugin_per_client_context *pcc, const char *argv[], const char *envp[])
{
    if (context->test_packet_filter)
    {
        if (!pcc->generated_pf_file)
        {
            const char *pff = get_env("pf_file", envp);
            const char *cn = get_env("username", envp);
            if (pff && cn)
            {
                char buf[256];
                snprintf(buf, sizeof(buf), "( sleep %d ; echo PF %s/%s ; cp \"%s.pf\" \"%s\" ) &",
                         context->test_packet_filter, cn, pff, cn, pff);
                printf("%s\n", buf);
                system(buf);
                pcc->generated_pf_file = true;
                return OPENVPN_PLUGIN_FUNC_SUCCESS;
            }
            else
            {
                return OPENVPN_PLUGIN_FUNC_ERROR;
            }
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

OPENVPN_EXPORT int
openvpn_plugin_func_v2(openvpn_plugin_handle_t handle,
                       const int type,
                       const char *argv[],
                       const char *envp[],
                       void *per_client_context,
                       struct openvpn_plugin_string_list **return_list)
{
    struct plugin_context *context = (struct plugin_context *) handle;
    struct plugin_per_client_context *pcc = (struct plugin_per_client_context *) per_client_context;
    switch (type)
    {
        case OPENVPN_PLUGIN_UP:
            printf("OPENVPN_PLUGIN_UP\n");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;

        case OPENVPN_PLUGIN_DOWN:
            printf("OPENVPN_PLUGIN_DOWN\n");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;

        case OPENVPN_PLUGIN_ROUTE_UP:
            printf("OPENVPN_PLUGIN_ROUTE_UP\n");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;

        case OPENVPN_PLUGIN_IPCHANGE:
            printf("OPENVPN_PLUGIN_IPCHANGE\n");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;

        case OPENVPN_PLUGIN_TLS_VERIFY:
            printf("OPENVPN_PLUGIN_TLS_VERIFY\n");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;

        case OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY:
            printf("OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY\n");
            return auth_user_pass_verify(context, pcc, argv, envp);

        case OPENVPN_PLUGIN_CLIENT_CONNECT_V2:
            printf("OPENVPN_PLUGIN_CLIENT_CONNECT_V2\n");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;

        case OPENVPN_PLUGIN_CLIENT_DISCONNECT:
            printf("OPENVPN_PLUGIN_CLIENT_DISCONNECT\n");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;

        case OPENVPN_PLUGIN_LEARN_ADDRESS:
            printf("OPENVPN_PLUGIN_LEARN_ADDRESS\n");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;

        case OPENVPN_PLUGIN_TLS_FINAL:
            printf("OPENVPN_PLUGIN_TLS_FINAL\n");
            return tls_final(context, pcc, argv, envp);

        case OPENVPN_PLUGIN_ENABLE_PF:
            printf("OPENVPN_PLUGIN_ENABLE_PF\n");
            if (context->test_packet_filter)
            {
                return OPENVPN_PLUGIN_FUNC_SUCCESS;
            }
            else
            {
                return OPENVPN_PLUGIN_FUNC_ERROR;
            }

        default:
            printf("OPENVPN_PLUGIN_?\n");
            return OPENVPN_PLUGIN_FUNC_ERROR;
    }
}

OPENVPN_EXPORT void *
openvpn_plugin_client_constructor_v1(openvpn_plugin_handle_t handle)
{
    printf("FUNC: openvpn_plugin_client_constructor_v1\n");
    return calloc(1, sizeof(struct plugin_per_client_context));
}

OPENVPN_EXPORT void
openvpn_plugin_client_destructor_v1(openvpn_plugin_handle_t handle, void *per_client_context)
{
    printf("FUNC: openvpn_plugin_client_destructor_v1\n");
    free(per_client_context);
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct plugin_context *context = (struct plugin_context *) handle;
    printf("FUNC: openvpn_plugin_close_v1\n");
    free(context);
}
