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

#ifdef HAVE_XKEY_PROVIDER

#include "syshead.h"
#include "error.h"
#include "buffer.h"
#include "xkey_common.h"

#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/core_names.h>
#include <openssl/store.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static const char *const props = XKEY_PROV_PROPS;

XKEY_EXTERNAL_SIGN_fn xkey_management_sign;

/**
 * Load external key for signing via management interface.
 * The public key must be passed in by the caller as we may not
 * be able to get it from the management.
 * Returns an EVP_PKEY object attached to xkey provider.
 * Caller must free it when no longer needed.
 */
EVP_PKEY *
xkey_load_management_key(OSSL_LIB_CTX *libctx, EVP_PKEY *pubkey)
{
    EVP_PKEY *pkey = NULL;
    ASSERT(pubkey);

    /* Management interface doesnt require any handle to be
     * stored in the key. We use a dummy pointer as we do need a
     * non-NULL value to indicate private key is avaialble.
     */
    void *dummy = & "dummy";

    const char *origin = "management";
    XKEY_EXTERNAL_SIGN_fn *sign_op = xkey_management_sign;

    /* UTF8 string pointers in here are only read from, so cast is safe */
    OSSL_PARAM params[] = {
        {"xkey-origin", OSSL_PARAM_UTF8_STRING, (char *) origin, 0, 0},
        {"pubkey", OSSL_PARAM_OCTET_STRING, &pubkey, sizeof(pubkey), 0},
        {"handle", OSSL_PARAM_OCTET_PTR, &dummy, sizeof(dummy), 0},
        {"sign_op", OSSL_PARAM_OCTET_PTR, (void **) &sign_op, sizeof(sign_op), 0},
        {NULL, 0, NULL, 0, 0}};

    /* Do not use EVP_PKEY_new_from_pkey as that will take keymgmt from pubkey */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, EVP_PKEY_get0_type_name(pubkey), props);
    if (!ctx
        || EVP_PKEY_fromdata_init(ctx) != 1
        || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1)
    {
        msg(M_NONFATAL, "Error loading key into ovpn.xkey provider");
    }
    if (ctx)
    {
        EVP_PKEY_CTX_free(ctx);
    }

    return pkey;
}

/* not yet implemented */
int
xkey_management_sign(void *unused, unsigned char *sig, size_t *siglen,
                     const unsigned char *tbs, size_t tbslen, XKEY_SIGALG alg)
{
    msg(M_FATAL, "FATAL ERROR: A sign callback for this key is not implemented.");
    return 0;
}

#endif /* HAVE_XKEY_PROVIDER */
