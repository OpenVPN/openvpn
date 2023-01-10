/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2017-2023 David Sommerseth <davids@openvpn.net>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "openvpn-plugin.h"

#define PLUGIN_NAME "base64.c"

/* Exported plug-in v3 API functions */
plugin_log_t ovpn_log = NULL;                      /**< Pointer to the OpenVPN log function.  See plugin_log() */
plugin_vlog_t ovpn_vlog = NULL;                    /**< Pointer to the OpenVPN vlog function. See plugin_vlog() */
plugin_base64_encode_t ovpn_base64_encode = NULL;  /**< Pointer to the openvpn_base64_encode () function */
plugin_base64_decode_t ovpn_base64_decode = NULL;  /**< Pointer to the openvpn_base64_decode () function */

/**
 * Search the environment pointer for a specific env var name
 *
 * PLEASE NOTE! The result is not valid outside the local
 * scope of the calling function.  Once the calling function
 * returns, any returned pointers are invalid.
 *
 * @param name  String containing the env.var name to search for
 * @param envp  String array pointer to the environment variable
 *
 * @return Returns a pointer to the value in the environment variable
 *         table on successful match.  Otherwise NULL is returned
 *
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


/**
 * This function is called when OpenVPN loads the plug-in.
 * The purpose is to initialize the plug-in and tell OpenVPN
 * which plug-in hooks this plug-in wants to be involved in
 *
 * For the arguments, see the include/openvpn-plugin.h file
 * for details on the function parameters
 *
 * @param v3structver  An integer containing the API version of
 *                     the plug-in structs OpenVPN uses
 * @param args         A pointer to the argument struct for
 *                     information and features provided by
 *                     OpenVPN to the plug-in
 * @param ret          A pointer to the struct OpenVPN uses to
 *                     receive information back from the plug-in
 *
 * @return Must return OPENVPN_PLUGIN_FUNC_SUCCESS when everything
 *         completed successfully.  Otherwise it must be returned
 *         OPENVPN_PLUGIN_FUNC_ERROR, which will stop OpenVPN
 *         from running
 *
 */
OPENVPN_EXPORT int
openvpn_plugin_open_v3(const int v3structver,
                       struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *ret)
{
    /* Check that we are API compatible */
    if (v3structver != OPENVPN_PLUGINv3_STRUCTVER)
    {
        printf("base64.c: ** ERROR ** Incompatible plug-in interface between this plug-in and OpenVPN\n");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /*  Which callbacks to intercept.  */
    ret->type_mask =
        OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_TLS_VERIFY)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_CONNECT_V2);

    /* we don't need a plug-in context in this example, but OpenVPN expects "something" */
    ret->handle = calloc(1, 1);

    /* Hook into the exported functions from OpenVPN */
    ovpn_log = args->callbacks->plugin_log;
    ovpn_vlog = args->callbacks->plugin_vlog;
    ovpn_base64_encode = args->callbacks->plugin_base64_encode;
    ovpn_base64_decode = args->callbacks->plugin_base64_decode;

    /* Print some version information about the OpenVPN process using this plug-in */
    ovpn_log(PLOG_NOTE, PLUGIN_NAME, "OpenVPN %s  (Major: %i, Minor: %i, Patch: %s)\n",
             args->ovpn_version, args->ovpn_version_major,
             args->ovpn_version_minor, args->ovpn_version_patch);

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}


/**
 * This function is called by OpenVPN each time the OpenVPN reaches
 * a point where plug-in calls should happen.  It only happens for those
 * plug-in hooks enabled in openvpn_plugin_open_v3().
 *
 * For the arguments, see the include/openvpn-plugin.h file
 * for details on the function parameters
 *
 * @param args        Pointer to a struct with details about the plug-in
 *                    call from the main OpenVPN process.
 * @param returndata  Pointer to a struct where the plug-in can provide
 *                    information back to OpenVPN to be processed
 *
 * @return  Must return OPENVPN_PLUGIN_FUNC_SUCCESS or
 *          OPENVPN_PLUGIN_FUNC_DEFERRED on success.  Otherwise it
 *          should return OPENVPN_FUNC_ERROR, which will stop and reject
 *          the client session from progressing.
 *
 */

OPENVPN_EXPORT int
openvpn_plugin_func_v1(openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[])
{
    if (type != OPENVPN_PLUGIN_TLS_VERIFY
        && type != OPENVPN_PLUGIN_CLIENT_CONNECT_V2)
    {
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "Unsupported plug-in hook call attempted");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* get username/password from envp string array */
    const char *clcert_cn = get_env("X509_0_CN", envp);
    if (!clcert_cn)
    {
        /* Ignore certificate checks not being a client certificate */
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }

    /* test the BASE64 encode function */
    char *buf = NULL;
    int r = ovpn_base64_encode(clcert_cn, strlen(clcert_cn), &buf);
    ovpn_log(PLOG_NOTE, PLUGIN_NAME, "BASE64 encoded '%s' (return value %i):  '%s'",
             clcert_cn, r, buf);

    /* test the BASE64 decode function */
    char buf2[256] = {0};
    r = ovpn_base64_decode(buf, &buf2, 255);
    ovpn_log(PLOG_NOTE, PLUGIN_NAME, "BASE64 decoded '%s' (return value %i):  '%s'",
             buf, r, buf2);

    /* Verify the result, and free the buffer allocated by ovpn_base64_encode() */
    r = strcmp(clcert_cn, buf2);
    free(buf);

    return (r == 0) ? OPENVPN_PLUGIN_FUNC_SUCCESS : OPENVPN_PLUGIN_FUNC_ERROR;
}


/**
 * This cleans up the last part of the plug-in, allows it to
 * shut down cleanly and release the plug-in global context buffer
 *
 * @param handle   Pointer to the plug-in global context buffer, which
 *                 need to be released by this function
 */
OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct plugin_context *context = (struct plugin_context *) handle;
    free(context);
}
