/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2021 Selva Nair <selva.nair@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by the
 *  Free Software Foundation, either version 2 of the License,
 *  or (at your option) any later version.
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
#include <config.h>
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"
#include "error.h"
#include "buffer.h"
#include "xkey_common.h"

#ifdef HAVE_XKEY_PROVIDER

#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/core_names.h>
#include <openssl/store.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* A descriptive name */
static const char *provname = "OpenVPN External Key Provider";

typedef struct
{
    OSSL_LIB_CTX *libctx;  /**< a child libctx for our own use */
} XKEY_PROVIDER_CTX;

/* helper to print debug messages */
#define xkey_dmsg(f, ...) \
        do {                                                        \
              dmsg(f|M_NOLF, "xkey_provider: In %s: ", __func__);    \
              dmsg(f|M_NOPREFIX, __VA_ARGS__);                      \
           } while(0)

/* main provider interface */

/* provider callbacks we implement */
static OSSL_FUNC_provider_query_operation_fn query_operation;
static OSSL_FUNC_provider_gettable_params_fn gettable_params;
static OSSL_FUNC_provider_get_params_fn get_params;
static OSSL_FUNC_provider_teardown_fn teardown;

static const OSSL_ALGORITHM *
query_operation(void *provctx, int op, int *no_store)
{
    xkey_dmsg(D_LOW, "op = %d", op);

    *no_store = 0;

    switch (op)
    {
        case OSSL_OP_SIGNATURE:
            return NULL;

        case OSSL_OP_KEYMGMT:
            return NULL;

        default:
            xkey_dmsg(D_LOW, "op not supported");
            break;
    }
    return NULL;
}

static const OSSL_PARAM *
gettable_params(void *provctx)
{
    xkey_dmsg(D_LOW, "entry");

    static const OSSL_PARAM param_types[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_END
    };

    return param_types;
}
static int
get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    xkey_dmsg(D_LOW, "entry");

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p)
    {
        return (OSSL_PARAM_set_utf8_ptr(p, provname) != 0);
    }

    return 0;
}

static void
teardown(void *provctx)
{
    xkey_dmsg(D_LOW, "entry");

    XKEY_PROVIDER_CTX *prov = provctx;
    if (prov && prov->libctx)
    {
        OSSL_LIB_CTX_free(prov->libctx);
    }
    OPENSSL_free(prov);
}

static const OSSL_DISPATCH dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void)) gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void)) get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) query_operation},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void)) teardown},
    {0, NULL}
};

int
xkey_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                   const OSSL_DISPATCH **out, void **provctx)
{
    XKEY_PROVIDER_CTX *prov;

    xkey_dmsg(D_LOW, "entry");

    prov = OPENSSL_zalloc(sizeof(*prov));
    if (!prov)
    {
        msg(M_NONFATAL, "xkey_provider_init: out of memory");
        return 0;
    }

    /* Make a child libctx for our use and set default prop query
     * on it to ensure calls we delegate won't loop back to us.
     */
    prov->libctx = OSSL_LIB_CTX_new_child(handle, in);

    EVP_set_default_properties(prov->libctx, "provider!=ovpn.xkey");

    *out = dispatch_table;
    *provctx = prov;

    return 1;
}

#endif /* HAVE_XKEY_PROVIDER */
