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
 * This file implements a Sample (HTTP) SSO OpenVPN plugin module
 *
 * See the README file for build instructions.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "openvpn-plugin.h"

#ifndef MAXPATH
#define MAXPATH 1024
#endif

#define ovpn_err(fmt, ...) \
    plugin->log(PLOG_ERR,   "SSO", fmt, ## __VA_ARGS__)
#define ovpn_dbg(fmt, ...) \
    plugin->log(PLOG_DEBUG, "SSO", fmt, ## __VA_ARGS__)
#define ovpn_note(fmt, ...) \
    plugin->log(PLOG_NOTE,  "SSO", fmt, ## __VA_ARGS__)

enum endpoint { CLIENT = 1, SERVER = 2 };

struct plugin {
    plugin_log_t log;
    enum endpoint type;
    int mask;
};

struct session {
    char user[48];
    char key [48];
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

OPENVPN_EXPORT int
openvpn_plugin_open_v3(const int version,
                       struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *rv)
{
    struct plugin *plugin = calloc(1, sizeof(*plugin));

    if (plugin == NULL)
    {
        printf("PLUGIN: allocating memory for context failed\n");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    plugin->type = get_env("remote_1", args->envp) ? CLIENT : SERVER;
    plugin->log  = args->callbacks->plugin_log;

    plugin->mask  = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_TLS_FINAL);
    plugin->mask |= OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_TLS_VERIFY);

    ovpn_note("vpn endpoint type=%s",plugin->type == CLIENT ? "client" : "server");

    rv->type_mask = plugin->mask;
    rv->handle = (void *)plugin;

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

static void
session_user_set(struct session *sess, X509 *x509)
{
    int fn_nid;
    ASN1_OBJECT *fn;
    ASN1_STRING *val;
    X509_NAME *x509_name;
    X509_NAME_ENTRY *ent;
    const char *objbuf;

    x509_name = X509_get_subject_name(x509);
    int i, n = X509_NAME_entry_count(x509_name);
    for (i = 0; i < n; ++i)
    {
        if (!(ent = X509_NAME_get_entry(x509_name, i)))
        {
            continue;
        }
        if (!(fn = X509_NAME_ENTRY_get_object(ent)))
        {
            continue;
        }
        if (!(val = X509_NAME_ENTRY_get_data(ent)))
        {
            continue;
        }
        if ((fn_nid = OBJ_obj2nid(fn)) == NID_undef)
        {
            continue;
        }
        if (!(objbuf = OBJ_nid2sn(fn_nid)))
        {
            continue;
        }
        unsigned char *buf = NULL;
        if (ASN1_STRING_to_UTF8(&buf, val) < 0)
        {
            continue;
        }

        if (!strncasecmp(objbuf, "CN", 2))
        {
            snprintf(sess->user, sizeof(sess->user) - 1, (char *)buf);
        }

        OPENSSL_free(buf);
    }
}

static int
tls_verify(struct openvpn_plugin_args_func_in const *args)
{
    struct plugin *plugin = (struct plugin  *)args->handle;
    struct session *sess  = (struct session *)args->per_client_context;

    /* we store cert subject for the server end point only */
    if (plugin->type != SERVER)
    {
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }

    if (!args->current_cert)
    {
        ovpn_err("this example plugin requires client certificate");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    session_user_set(sess, args->current_cert);

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

static void
file_store(char *file, char *content)
{
    FILE *f;
    if (!(f = fopen(file, "w+")))
    {
        return;
    }

    fprintf(f, "%s", content);
    fclose(f);
}

static void
server_store(struct openvpn_plugin_args_func_in const *args)
{
    struct plugin *plugin = (struct plugin  *)args->handle;
    struct session *sess  = (struct session *)args->per_client_context;

    char file[MAXPATH];
    snprintf(file, sizeof(file) - 1, "/tmp/openvpn_sso_%s", sess->key);
    ovpn_note("app session file: %s", file);
    file_store(file, sess->user);
}

static void
client_store(struct openvpn_plugin_args_func_in const *args)
{
    struct plugin *plugin = (struct plugin  *)args->handle;
    struct session *sess  = (struct session *)args->per_client_context;

    char *file = "/tmp/openvpn_sso_user";
    ovpn_note("app session file: %s", file);
    file_store(file, sess->key);
}

static int
tls_final(struct openvpn_plugin_args_func_in const *args,
          struct openvpn_plugin_args_func_return *rv)
{
    struct plugin *plugin = (struct plugin  *)args->handle;
    struct session *sess  = (struct session *)args->per_client_context;

    const char *key;
    if (!(key = get_env("exported_keying_material", args->envp)))
    {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    snprintf(sess->key, sizeof(sess->key) - 1, "%s", key);
    ovpn_note("app session key:  %s", sess->key);

    switch (plugin->type)
    {
        case SERVER:
            server_store(args);
            break;

        case CLIENT:
            client_store(args);
            return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }

    ovpn_note("app session user: %s", sess->user);
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3(const int version,
                       struct openvpn_plugin_args_func_in const *args,
                       struct openvpn_plugin_args_func_return *rv)
{
    switch (args->type)
    {
        case OPENVPN_PLUGIN_TLS_VERIFY:
            return tls_verify(args);

        case OPENVPN_PLUGIN_TLS_FINAL:
            return tls_final(args, rv);
    }
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void *
openvpn_plugin_client_constructor_v1(openvpn_plugin_handle_t handle)
{
    struct plugin *plugin = (struct plugin *)handle;
    struct session *sess  = calloc(1, sizeof(*sess));

    ovpn_note("app session created");

    return (void *)sess;
}

OPENVPN_EXPORT void
openvpn_plugin_client_destructor_v1(openvpn_plugin_handle_t handle, void *ctx)
{
    struct plugin *plugin = (struct plugin *)handle;
    struct session *sess  = (struct session *)ctx;

    ovpn_note("app session key: %s", sess->key);
    ovpn_note("app session destroyed");

    free(sess);
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct plugin *plugin = (struct plugin *)handle;
    free(plugin);
}
