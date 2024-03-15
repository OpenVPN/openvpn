/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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
 * plug-in support, using dynamically loaded libraries
 */

#ifndef OPENVPN_PLUGIN_H
#define OPENVPN_PLUGIN_H

#ifdef ENABLE_CRYPTO_OPENSSL
#include "ssl_verify_openssl.h"
#endif
#ifdef ENABLE_CRYPTO_MBEDTLS
#include "ssl_verify_mbedtls.h"
#endif
#include "openvpn-plugin.h"

#ifdef ENABLE_PLUGIN

#include "misc.h"

#define MAX_PLUGINS 16

struct plugin_option {
    const char *so_pathname;
    const char **argv;
};

struct plugin_option_list {
    int n;
    struct plugin_option plugins[MAX_PLUGINS];
};

struct plugin {
    bool initialized;
    const char *so_pathname;
    unsigned int plugin_type_mask;
    int requested_initialization_point;

#ifndef _WIN32
    void *handle;
#else
    HMODULE module;
#endif

    openvpn_plugin_open_v1 open1;
    openvpn_plugin_open_v2 open2;
    openvpn_plugin_open_v3 open3;
    openvpn_plugin_func_v1 func1;
    openvpn_plugin_func_v2 func2;
    openvpn_plugin_func_v3 func3;
    openvpn_plugin_close_v1 close;
    openvpn_plugin_abort_v1 abort;
    openvpn_plugin_client_constructor_v1 client_constructor;
    openvpn_plugin_client_destructor_v1 client_destructor;
    openvpn_plugin_min_version_required_v1 min_version_required;
    openvpn_plugin_select_initialization_point_v1 initialization_point;

    openvpn_plugin_handle_t plugin_handle;
};

struct plugin_per_client
{
    void *per_client_context[MAX_PLUGINS];
};

struct plugin_common
{
    int n;
    struct plugin plugins[MAX_PLUGINS];
};

struct plugin_list
{
    struct plugin_per_client per_client;
    struct plugin_common *common;
    bool common_owned;
};

struct plugin_return
{
    int n;
    struct openvpn_plugin_string_list *list[MAX_PLUGINS];
};

struct plugin_option_list *plugin_option_list_new(struct gc_arena *gc);

bool plugin_option_list_add(struct plugin_option_list *list, char **p,
                            struct gc_arena *gc);

#ifndef ENABLE_SMALL
void plugin_option_list_print(const struct plugin_option_list *list, int msglevel);

#endif

struct plugin_list *plugin_list_init(const struct plugin_option_list *list);

void plugin_list_open(struct plugin_list *pl,
                      const struct plugin_option_list *list,
                      struct plugin_return *pr,
                      const struct env_set *es,
                      const int init_point);

struct plugin_list *plugin_list_inherit(const struct plugin_list *src);

int plugin_call_ssl(const struct plugin_list *pl,
                    const int type,
                    const struct argv *av,
                    struct plugin_return *pr,
                    struct env_set *es,
                    int current_cert_depth,
                    openvpn_x509_cert_t *current_cert
                    );

void plugin_list_close(struct plugin_list *pl);

bool plugin_defined(const struct plugin_list *pl, const int type);

void plugin_return_get_column(const struct plugin_return *src,
                              struct plugin_return *dest,
                              const char *colname);

void plugin_return_free(struct plugin_return *pr);

#ifdef ENABLE_DEBUG
void plugin_return_print(const int msglevel, const char *prefix, const struct plugin_return *pr);

#endif

static inline int
plugin_n(const struct plugin_list *pl)
{
    if (pl && pl->common)
    {
        return pl->common->n;
    }
    else
    {
        return 0;
    }
}

static inline bool
plugin_return_defined(const struct plugin_return *pr)
{
    return pr->n >= 0;
}

static inline void
plugin_return_init(struct plugin_return *pr)
{
    pr->n = 0;
}

#else  /* ifdef ENABLE_PLUGIN */
struct plugin_list { int dummy; };
struct plugin_return { int dummy; };

static inline bool
plugin_defined(const struct plugin_list *pl, const int type)
{
    return false;
}

static inline int
plugin_call_ssl(const struct plugin_list *pl,
                const int type,
                const struct argv *av,
                struct plugin_return *pr,
                struct env_set *es,
                int current_cert_depth,
                openvpn_x509_cert_t *current_cert
                )
{
    return 0;
}

#endif /* ENABLE_PLUGIN */

static inline int
plugin_call(const struct plugin_list *pl,
            const int type,
            const struct argv *av,
            struct plugin_return *pr,
            struct env_set *es)
{
    return plugin_call_ssl(pl, type, av, pr, es, -1, NULL);
}

void plugin_abort(void);

#endif /* OPENVPN_PLUGIN_H */
