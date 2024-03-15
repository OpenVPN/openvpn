/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2021-2024 Selva Nair <selva.nair@gmail.com>
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

typedef enum
{
    ORIGIN_UNDEFINED = 0,
    OPENSSL_NATIVE, /* native key imported in */
    EXTERNAL_KEY
} XKEY_ORIGIN;

/**
 * XKEY_KEYDATA: Our keydata encapsulation:
 *
 * We keep an opaque handle provided by the backend for the loaded
 * key. It's passed back to the backend for any operation on private
 * keys --- in practice, sign() op only.
 *
 * We also keep the public key in the form of a native OpenSSL EVP_PKEY.
 * This allows us to do all public ops by calling ops in the default provider.
 * Both these are references retained by us and freed when the key is
 * destroyed. As the pubkey is native, we free it using EVP_PKEY_free().
 * To free the handle we call the backend if a free function
 * has been set for that key. It could be set when the key is
 * created/imported.
 * For native keys, there is no need to free the handle as its either
 * NULL of the same as the pubkey which we always free.
 */
typedef struct
{
    /** opaque handle dependent on KEY_ORIGIN -- could be NULL */
    void *handle;
    /** associated public key as an openvpn native key */
    EVP_PKEY *pubkey;
    /** origin of key -- native or external */
    XKEY_ORIGIN origin;
    /** sign function in backend to call */
    XKEY_EXTERNAL_SIGN_fn *sign;
    /** keydata handle free function of backend */
    XKEY_PRIVKEY_FREE_fn *free;
    XKEY_PROVIDER_CTX *prov;
    int refcount;                /**< reference count */
} XKEY_KEYDATA;

static inline const char *
get_keytype(const XKEY_KEYDATA *key)
{
    int keytype = key->pubkey ? EVP_PKEY_get_id(key->pubkey) : 0;

    switch (keytype)
    {
        case EVP_PKEY_RSA:
            return "RSA";

        case EVP_PKEY_ED448:
            return "ED448";

        case EVP_PKEY_ED25519:
            return "ED25519";

        default:
            return "EC";
    }
}


static int
KEYSIZE(const XKEY_KEYDATA *key)
{
    return key->pubkey ? EVP_PKEY_get_size(key->pubkey) : 0;
}

/**
 * Helper sign function for native keys
 * Implemented using OpenSSL calls.
 */
int
xkey_native_sign(XKEY_KEYDATA *key, unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen, XKEY_SIGALG sigalg);


/* keymgmt provider */

/* keymgmt callbacks we implement */
static OSSL_FUNC_keymgmt_new_fn keymgmt_new;
static OSSL_FUNC_keymgmt_free_fn keymgmt_free;
static OSSL_FUNC_keymgmt_load_fn keymgmt_load;
static OSSL_FUNC_keymgmt_has_fn keymgmt_has;
static OSSL_FUNC_keymgmt_match_fn keymgmt_match;
static OSSL_FUNC_keymgmt_import_fn rsa_keymgmt_import;
static OSSL_FUNC_keymgmt_import_fn ec_keymgmt_import;
static OSSL_FUNC_keymgmt_import_types_fn keymgmt_import_types;
static OSSL_FUNC_keymgmt_get_params_fn keymgmt_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn keymgmt_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn keymgmt_set_params;
static OSSL_FUNC_keymgmt_query_operation_name_fn rsa_keymgmt_name;
static OSSL_FUNC_keymgmt_query_operation_name_fn ec_keymgmt_name;

static int
keymgmt_import_helper(XKEY_KEYDATA *key, const OSSL_PARAM params[]);

static XKEY_KEYDATA *
keydata_new()
{
    xkey_dmsg(D_XKEY, "entry");

    XKEY_KEYDATA *key = OPENSSL_zalloc(sizeof(*key));
    if (!key)
    {
        msg(M_NONFATAL, "xkey_keydata_new: out of memory");
    }

    return key;
}

static void
keydata_free(XKEY_KEYDATA *key)
{
    xkey_dmsg(D_XKEY, "entry");

    if (!key || key->refcount-- > 0) /* free when refcount goes to zero */
    {
        return;
    }
    if (key->free && key->handle)
    {
        key->free(key->handle);
        key->handle = NULL;
    }
    if (key->pubkey)
    {
        EVP_PKEY_free(key->pubkey);
    }
    OPENSSL_free(key);
}

static void *
keymgmt_new(void *provctx)
{
    xkey_dmsg(D_XKEY, "entry");

    XKEY_KEYDATA *key = keydata_new();
    if (key)
    {
        key->prov = provctx;
    }

    return key;
}

static void *
keymgmt_load(const void *reference, size_t reference_sz)
{
    xkey_dmsg(D_XKEY, "entry");

    return NULL;
}

/**
 * Key import function
 * When key operations like sign/verify are done in our context
 * the key gets imported into us. We will also use import to
 * load an external key into the provider.
 *
 * For native keys we get called with standard OpenSSL params
 * appropriate for the key. We just use it to create a native
 * EVP_PKEY from params and assign to keydata->handle.
 *
 * For non-native keys the params[] array should include a custom
 * value with name "xkey-origin".
 *
 * Other required parameters in the params array are:
 *
 *  pubkey - pointer to native public key as a OCTET_STRING
 *           the public key is duplicated on receipt
 *  handle - reference to opaque handle to private key -- if not required
 *           pass a dummy value that is not zero. type = OCTET_PTR
 *           The reference is retained -- caller must _not_ free it.
 *  sign_op - function pointer for sign operation. type = OCTET_PTR
 *            Must be a reference to XKEY_EXTERNAL_SIGN_fn
 *  xkey-origin - A custom string to indicate the external key origin. UTF8_STRING
 *                The value doesn't really matter, but must be present.
 *
 * Optional params
 *  free_op - Called as free(handle) when the key is deleted. If the
 *           handle should not be freed, do not include. type = OCTET_PTR
 *           Must be a reference to XKEY_PRIVKEY_FREE_fn
 *
 *  See xkey_load_management_key for an example use.
 */
static int
keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[], const char *name)
{
    xkey_dmsg(D_XKEY, "entry");

    XKEY_KEYDATA *key = keydata;
    ASSERT(key);

    /* Our private key is immutable -- we import only if keydata is empty */
    if (key->handle || key->pubkey)
    {
        msg(M_WARN, "Error: keymgmt_import: keydata not empty -- our keys are immutable");
        return 0;
    }

    /* if params contain a custom origin, call our helper to import custom keys */
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, "xkey-origin");
    if (p && p->data_type == OSSL_PARAM_UTF8_STRING)
    {
        key->origin = EXTERNAL_KEY;
        xkey_dmsg(D_XKEY, "importing external key");
        return keymgmt_import_helper(key, params);
    }

    xkey_dmsg(D_XKEY, "importing native key");

    /* create a native public key and assign it to key->pubkey */
    EVP_PKEY *pkey = NULL;
    int selection_pub = selection & ~OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(key->prov->libctx, name, NULL);
    if (!ctx
        || (EVP_PKEY_fromdata_init(ctx) != 1)
        || (EVP_PKEY_fromdata(ctx, &pkey, selection_pub, (OSSL_PARAM *) params) !=1))
    {
        msg(M_WARN, "Error: keymgmt_import failed for key type <%s>", name);
        if (pkey)
        {
            EVP_PKEY_free(pkey);
        }
        if (ctx)
        {
            EVP_PKEY_CTX_free(ctx);
        }
        return 0;
    }

    key->pubkey = pkey;
    key->origin = OPENSSL_NATIVE;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
    {
        /* create private key */
        pkey = NULL;
        if (EVP_PKEY_fromdata(ctx, &pkey, selection, (OSSL_PARAM *) params) == 1)
        {
            key->handle = pkey;
            key->free = (XKEY_PRIVKEY_FREE_fn *) EVP_PKEY_free;
        }
    }
    EVP_PKEY_CTX_free(ctx);

    xkey_dmsg(D_XKEY, "imported native %s key", EVP_PKEY_get0_type_name(pkey));
    return 1;
}

static int
rsa_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    xkey_dmsg(D_XKEY, "entry");

    return keymgmt_import(keydata, selection, params, "RSA");
}

static int
ec_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    xkey_dmsg(D_XKEY, "entry");

    return keymgmt_import(keydata, selection, params, "EC");
}

static int
ed448_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    xkey_dmsg(D_XKEY, "entry");

    return keymgmt_import(keydata, selection, params, "ED448");
}

static int
ed25519_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    xkey_dmsg(D_XKEY, "entry");

    return keymgmt_import(keydata, selection, params, "ED25519");
}

/* This function has to exist for key import to work
 * though we do not support import of individual params
 * like n or e. We simply return an empty list here for
 * both rsa and ec, which works.
 */
static const OSSL_PARAM *
keymgmt_import_types(int selection)
{
    xkey_dmsg(D_XKEY, "entry");

    static const OSSL_PARAM key_types[] = { OSSL_PARAM_END };

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        return key_types;
    }
    return NULL;
}

static void
keymgmt_free(void *keydata)
{
    xkey_dmsg(D_XKEY, "entry");

    keydata_free(keydata);
}

static int
keymgmt_has(const void *keydata, int selection)
{
    xkey_dmsg(D_XKEY, "selection = %d", selection);

    const XKEY_KEYDATA *key = keydata;
    int ok = (key != NULL);

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        ok = ok && key->pubkey;
    }
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
    {
        ok = ok && key->handle;
    }

    return ok;
}

static int
keymgmt_match(const void *keydata1, const void *keydata2, int selection)
{
    const XKEY_KEYDATA *key1 = keydata1;
    const XKEY_KEYDATA *key2 = keydata2;

    xkey_dmsg(D_XKEY, "entry");

    int ret = key1 && key2 && key1->pubkey && key2->pubkey;

    /* our keys always have pubkey -- we only match them */

    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
    {
        ret = ret && EVP_PKEY_eq(key1->pubkey, key2->pubkey);
        xkey_dmsg(D_XKEY, "checking key pair match: res = %d", ret);
    }

    if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)
    {
        ret = ret && EVP_PKEY_parameters_eq(key1->pubkey, key2->pubkey);
        xkey_dmsg(D_XKEY, "checking parameter match: res = %d", ret);
    }

    return ret;
}

/* A minimal set of key params that we can return */
static const OSSL_PARAM *
keymgmt_gettable_params(void *provctx)
{
    xkey_dmsg(D_XKEY, "entry");

    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END
    };
    return gettable;
}

static int
keymgmt_get_params(void *keydata, OSSL_PARAM *params)
{
    xkey_dmsg(D_XKEY, "entry");

    XKEY_KEYDATA *key = keydata;
    if (!key || !key->pubkey)
    {
        return 0;
    }

    return EVP_PKEY_get_params(key->pubkey, params);
}

/* Helper used by keymgmt_import and keymgmt_set_params
 * for our keys. Not to be used for OpenSSL native keys.
 */
static int
keymgmt_import_helper(XKEY_KEYDATA *key, const OSSL_PARAM *params)
{
    xkey_dmsg(D_XKEY, "entry");

    const OSSL_PARAM *p;
    EVP_PKEY *pkey = NULL;

    ASSERT(key);
    /* calling this with native keys is a coding error */
    ASSERT(key->origin != OPENSSL_NATIVE);

    if (params == NULL)
    {
        return 1; /* not an error */
    }

    /* our keys are immutable, we do not allow resetting parameters */
    if (key->pubkey)
    {
        return 0;
    }

    /* only check params we understand and ignore the rest */

    p = OSSL_PARAM_locate_const(params, "pubkey"); /*setting pubkey on our keydata */
    if (p && p->data_type == OSSL_PARAM_OCTET_STRING
        && p->data_size == sizeof(pkey))
    {
        pkey = *(EVP_PKEY **)p->data;
        ASSERT(pkey);

        int id = EVP_PKEY_get_id(pkey);
        if (id != EVP_PKEY_RSA && id != EVP_PKEY_EC && id != EVP_PKEY_ED25519 && id != EVP_PKEY_ED448)
        {
            msg(M_WARN, "Error: xkey keymgmt_import: unknown key type (%d)", id);
            return 0;
        }

        key->pubkey = EVP_PKEY_dup(pkey);
        if (key->pubkey == NULL)
        {
            msg(M_NONFATAL, "Error: xkey keymgmt_import: duplicating pubkey failed.");
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, "handle"); /*setting privkey */
    if (p && p->data_type == OSSL_PARAM_OCTET_PTR
        && p->data_size == sizeof(key->handle))
    {
        key->handle = *(void **)p->data;
        /* caller should keep the reference alive until we call free */
        ASSERT(key->handle); /* fix your params array */
    }

    p = OSSL_PARAM_locate_const(params, "sign_op"); /*setting sign_op */
    if (p && p->data_type == OSSL_PARAM_OCTET_PTR
        && p->data_size == sizeof(key->sign))
    {
        key->sign = *(void **)p->data;
        ASSERT(key->sign); /* fix your params array */
    }

    /* optional parameters */
    p = OSSL_PARAM_locate_const(params, "free_op"); /*setting free_op */
    if (p && p->data_type == OSSL_PARAM_OCTET_PTR
        && p->data_size == sizeof(key->free))
    {
        key->free = *(void **)p->data;
    }
    xkey_dmsg(D_XKEY, "imported external %s key", EVP_PKEY_get0_type_name(key->pubkey));

    return 1;
}

/**
 * Set params on a key.
 *
 * If the key is an encapsulated native key, we just call
 * EVP_PKEY_set_params in the default context. Only those params
 * supported by the default provider would work in this case.
 *
 * We treat our key object as immutable, so this works only with an
 * empty key. Supported params for external keys are the
 * same as those listed in the description of keymgmt_import.
 */
static int
keymgmt_set_params(void *keydata, const OSSL_PARAM *params)
{
    XKEY_KEYDATA *key = keydata;
    ASSERT(key);

    xkey_dmsg(D_XKEY, "entry");

    if (key->origin != OPENSSL_NATIVE)
    {
        return keymgmt_import_helper(key, params);
    }
    else if (key->handle == NULL) /* once handle is set our key is immutable */
    {
        /* pubkey is always native -- just delegate */
        return EVP_PKEY_set_params(key->pubkey, (OSSL_PARAM *)params);
    }
    else
    {
        msg(M_WARN, "xkey keymgmt_set_params: key is immutable");
    }
    return 1;
}

static const char *
rsa_keymgmt_name(int id)
{
    xkey_dmsg(D_XKEY, "entry");

    return "RSA";
}

static const char *
ec_keymgmt_name(int id)
{
    xkey_dmsg(D_XKEY, "entry");

    if (id == OSSL_OP_SIGNATURE)
    {
        return "ECDSA";
    }
    /* though we do not implement keyexch we could be queried for
     * keyexch mechanism supported by EC keys
     */
    else if (id == OSSL_OP_KEYEXCH)
    {
        return "ECDH";
    }

    msg(D_XKEY, "xkey ec_keymgmt_name called with op_id != SIGNATURE or KEYEXCH id=%d", id);
    return "EC";
}

static const OSSL_DISPATCH rsa_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))keymgmt_new},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))keymgmt_free},
    {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))keymgmt_load},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))rsa_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))keymgmt_import_types},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))keymgmt_gettable_params},   /* same as gettable */
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))rsa_keymgmt_name},
    {0, NULL }
};

static const OSSL_DISPATCH ec_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))keymgmt_new},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))keymgmt_free},
    {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))keymgmt_load},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ec_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))keymgmt_import_types},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))keymgmt_gettable_params},   /* same as gettable */
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))ec_keymgmt_name},
    {0, NULL }
};

static const OSSL_DISPATCH ed448_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))keymgmt_new},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))keymgmt_free},
    {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))keymgmt_load},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ed448_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))keymgmt_import_types},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))keymgmt_gettable_params},       /* same as gettable */
    {0, NULL }
};

static const OSSL_DISPATCH ed25519_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))keymgmt_new},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))keymgmt_free},
    {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))keymgmt_load},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ed25519_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))keymgmt_import_types},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))keymgmt_gettable_params},       /* same as gettable */
    {0, NULL }
};


const OSSL_ALGORITHM keymgmts[] = {
    {"RSA:rsaEncryption", XKEY_PROV_PROPS, rsa_keymgmt_functions, "OpenVPN xkey RSA Key Manager"},
    {"RSA-PSS:RSASSA-PSS", XKEY_PROV_PROPS, rsa_keymgmt_functions, "OpenVPN xkey RSA-PSS Key Manager"},
    {"EC:id-ecPublicKey", XKEY_PROV_PROPS, ec_keymgmt_functions, "OpenVPN xkey EC Key Manager"},
    {"ED448", XKEY_PROV_PROPS, ed448_keymgmt_functions, "OpenVPN xkey ED448 Key Manager"},
    {"ED25519", XKEY_PROV_PROPS, ed25519_keymgmt_functions, "OpenVPN xkey ED25519 Key Manager"},
    {NULL, NULL, NULL, NULL}
};


/* signature provider */

/* signature provider callbacks we provide */
static OSSL_FUNC_signature_newctx_fn signature_newctx;
static OSSL_FUNC_signature_freectx_fn signature_freectx;
static OSSL_FUNC_signature_sign_init_fn signature_sign_init;
static OSSL_FUNC_signature_sign_fn signature_sign;
static OSSL_FUNC_signature_digest_verify_init_fn signature_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_fn signature_digest_verify;
static OSSL_FUNC_signature_digest_sign_init_fn signature_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_fn signature_digest_sign;
static OSSL_FUNC_signature_set_ctx_params_fn signature_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn signature_settable_ctx_params;
static OSSL_FUNC_signature_get_ctx_params_fn signature_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn signature_gettable_ctx_params;

typedef struct
{
    XKEY_PROVIDER_CTX *prov;
    XKEY_KEYDATA *keydata;
    XKEY_SIGALG sigalg;
} XKEY_SIGNATURE_CTX;

static const XKEY_SIGALG default_sigalg = { .mdname = "MD5-SHA1", .saltlen = "digest",
                                            .padmode = "pkcs1", .keytype = "RSA"};

const struct {
    int nid;
    const char *name;
} digest_names[] = {{NID_md5_sha1, "MD5-SHA1"}, {NID_sha1, "SHA1"},
                    {NID_sha224, "SHA224", }, {NID_sha256, "SHA256"}, {NID_sha384, "SHA384"},
                    {NID_sha512, "SHA512"}, {0, NULL}};
/* Use of NIDs as opposed to EVP_MD_fetch is okay here
 * as these are only used for converting names passed in
 * by OpenSSL to const strings.
 */

static struct {
    int id;
    const char *name;
} padmode_names[] = {{RSA_PKCS1_PADDING, "pkcs1"},
                     {RSA_PKCS1_PSS_PADDING, "pss"},
                     {RSA_NO_PADDING, "none"},
                     {0, NULL}};

static const char *saltlen_names[] = {"digest", "max", "auto", NULL};

/* Return a string literal for digest name - normalizes
 * alternate names like SHA2-256 to SHA256 etc.
 */
static const char *
xkey_mdname(const char *name)
{
    if (name == NULL)
    {
        return "none";
    }

    int i = 0;

    int nid = EVP_MD_get_type(EVP_get_digestbyname(name));

    while (digest_names[i].name && nid != digest_names[i].nid)
    {
        i++;
    }
    return digest_names[i].name ?  digest_names[i].name : "MD5-SHA1";
}

static void *
signature_newctx(void *provctx, const char *propq)
{
    xkey_dmsg(D_XKEY, "entry");

    (void) propq; /* unused */

    XKEY_SIGNATURE_CTX *sctx = OPENSSL_zalloc(sizeof(*sctx));
    if (!sctx)
    {
        msg(M_NONFATAL, "xkey_signature_newctx: out of memory");
        return NULL;
    }

    sctx->prov = provctx;
    sctx->sigalg = default_sigalg;

    return sctx;
}

static void
signature_freectx(void *ctx)
{
    xkey_dmsg(D_XKEY, "entry");

    XKEY_SIGNATURE_CTX *sctx = ctx;

    keydata_free(sctx->keydata);

    OPENSSL_free(sctx);
}

static const OSSL_PARAM *
signature_settable_ctx_params(void *ctx, void *provctx)
{
    xkey_dmsg(D_XKEY, "entry");

    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}

static int
signature_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    xkey_dmsg(D_XKEY, "entry");

    XKEY_SIGNATURE_CTX *sctx = ctx;
    const OSSL_PARAM *p;

    if (params == NULL)
    {
        return 1;  /* not an error */
    }
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p && p->data_type == OSSL_PARAM_UTF8_STRING)
    {
        sctx->sigalg.padmode = NULL;
        for (int i = 0; padmode_names[i].id != 0; i++)
        {
            if (!strcmp(p->data, padmode_names[i].name))
            {
                sctx->sigalg.padmode = padmode_names[i].name;
                break;
            }
        }
        if (sctx->sigalg.padmode == NULL)
        {
            msg(M_WARN, "xkey signature_ctx: padmode <%s>, treating as <none>",
                (char *)p->data);
            sctx->sigalg.padmode = "none";
        }
        xkey_dmsg(D_XKEY, "setting padmode as %s", sctx->sigalg.padmode);
    }
    else if (p && p->data_type == OSSL_PARAM_INTEGER)
    {
        sctx->sigalg.padmode = NULL;
        int padmode = 0;
        if (OSSL_PARAM_get_int(p, &padmode))
        {
            for (int i = 0; padmode_names[i].id != 0; i++)
            {
                if (padmode == padmode_names[i].id)
                {
                    sctx->sigalg.padmode = padmode_names[i].name;
                    break;
                }
            }
        }
        if (padmode == 0 || sctx->sigalg.padmode == NULL)
        {
            msg(M_WARN, "xkey signature_ctx: padmode <%d>, treating as <none>", padmode);
            sctx->sigalg.padmode = "none";
        }
        xkey_dmsg(D_XKEY, "setting padmode <%s>", sctx->sigalg.padmode);
    }
    else if (p)
    {
        msg(M_WARN, "xkey_signature_params: unknown padmode ignored");
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p  &&  p->data_type == OSSL_PARAM_UTF8_STRING)
    {
        sctx->sigalg.mdname = xkey_mdname(p->data);
        xkey_dmsg(D_XKEY, "setting hashalg as %s", sctx->sigalg.mdname);
    }
    else if (p)
    {
        msg(M_WARN, "xkey_signature_params: unknown digest type ignored");
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p && p->data_type == OSSL_PARAM_UTF8_STRING)
    {
        sctx->sigalg.saltlen = NULL;
        for (int i = 0; saltlen_names[i] != NULL; i++)
        {
            if (!strcmp(p->data, saltlen_names[i]))
            {
                sctx->sigalg.saltlen = saltlen_names[i];
                break;
            }
        }
        if (sctx->sigalg.saltlen == NULL)
        {
            msg(M_WARN, "xkey_signature_params: unknown saltlen <%s>",
                (char *)p->data);
            sctx->sigalg.saltlen = "digest"; /* most common */
        }
        xkey_dmsg(D_XKEY, "setting saltlen to %s", sctx->sigalg.saltlen);
    }
    else if (p)
    {
        msg(M_WARN, "xkey_signature_params: unknown saltlen ignored");
    }

    return 1;
}

static const OSSL_PARAM *
signature_gettable_ctx_params(void *ctx, void *provctx)
{
    xkey_dmsg(D_XKEY, "entry");

    static OSSL_PARAM gettable[] = { OSSL_PARAM_END }; /* Empty list */

    return gettable;
}

static int
signature_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    xkey_dmsg(D_XKEY, "not implemented");
    return 0;
}

static int
signature_sign_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    xkey_dmsg(D_XKEY, "entry");

    XKEY_SIGNATURE_CTX *sctx = ctx;

    if (sctx->keydata)
    {
        keydata_free(sctx->keydata);
    }
    sctx->keydata = provkey;
    sctx->keydata->refcount++; /* we are keeping a copy */
    sctx->sigalg.keytype = get_keytype(sctx->keydata);

    signature_set_ctx_params(sctx, params);

    return 1;
}

/* Sign digest or message using sign function */
static int
xkey_sign_dispatch(XKEY_SIGNATURE_CTX *sctx, unsigned char *sig, size_t *siglen,
                   const unsigned char *tbs, size_t tbslen)
{
    XKEY_EXTERNAL_SIGN_fn *sign = sctx->keydata->sign;
    int ret = 0;

    if (sctx->keydata->origin == OPENSSL_NATIVE)
    {
        ret = xkey_native_sign(sctx->keydata, sig, siglen, tbs, tbslen, sctx->sigalg);
    }
    else if (sign)
    {
        ret = sign(sctx->keydata->handle, sig, siglen, tbs, tbslen, sctx->sigalg);
        xkey_dmsg(D_XKEY, "xkey_provider: external sign op returned ret = %d siglen = %d", ret, (int) *siglen);
    }
    else
    {
        msg(M_NONFATAL, "xkey_provider: Internal error: No sign callback for external key.");
    }

    return ret;
}

static int
signature_sign(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize,
               const unsigned char *tbs, size_t tbslen)
{
    xkey_dmsg(D_XKEY, "entry with siglen = %zu\n", *siglen);

    XKEY_SIGNATURE_CTX *sctx = ctx;
    ASSERT(sctx);
    ASSERT(sctx->keydata);

    if (!sig)
    {
        *siglen = KEYSIZE(sctx->keydata);
        return 1;
    }

    sctx->sigalg.op = "Sign";
    return xkey_sign_dispatch(sctx, sig, siglen, tbs, tbslen);
}

static int
signature_digest_verify_init(void *ctx, const char *mdname, void *provkey,
                             const OSSL_PARAM params[])
{
    xkey_dmsg(D_XKEY, "mdname <%s>", mdname);

    msg(M_WARN, "xkey_provider: DigestVerifyInit is not implemented");
    return 0;
}

/* We do not expect to be called for DigestVerify() but still
 * return an empty function for it in the sign dispatch array
 * for debugging purposes.
 */
static int
signature_digest_verify(void *ctx, const unsigned char *sig, size_t siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    xkey_dmsg(D_XKEY, "entry");

    msg(M_WARN, "xkey_provider: DigestVerify is not implemented");
    return 0;
}

static int
signature_digest_sign_init(void *ctx, const char *mdname,
                           void *provkey, const OSSL_PARAM params[])
{
    xkey_dmsg(D_XKEY, "mdname = <%s>", mdname);

    XKEY_SIGNATURE_CTX *sctx = ctx;

    ASSERT(sctx);
    ASSERT(provkey);
    ASSERT(sctx->prov);

    if (sctx->keydata)
    {
        keydata_free(sctx->keydata);
    }
    sctx->keydata = provkey; /* used by digest_sign */
    sctx->keydata->refcount++;
    sctx->sigalg.keytype = get_keytype(sctx->keydata);

    signature_set_ctx_params(ctx, params);
    if (!strcmp(sctx->sigalg.keytype, "ED448") || !strcmp(sctx->sigalg.keytype, "ED25519"))
    {
        /* EdDSA requires NULL as digest for the DigestSign API instead
         * of using the normal Sign API. Ensure it is actually NULL too */
        if (mdname != NULL)
        {
            msg(M_WARN, "xkey digest_sign_init: mdname must be NULL for ED448/ED25519.");
            return 0;
        }
        sctx->sigalg.mdname = "none";
    }
    else if (mdname)
    {
        sctx->sigalg.mdname = xkey_mdname(mdname); /* get a string literal pointer */
    }
    else
    {
        msg(M_WARN, "xkey digest_sign_init: mdname is NULL.");
    }
    return 1;
}

static int
signature_digest_sign(void *ctx, unsigned char *sig, size_t *siglen,
                      size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    xkey_dmsg(D_XKEY, "entry");

    XKEY_SIGNATURE_CTX *sctx = ctx;

    ASSERT(sctx);
    ASSERT(sctx->keydata);

    if (!sig) /* set siglen and return */
    {
        *siglen = KEYSIZE(sctx->keydata);
        return 1;
    }

    if (sctx->keydata->origin != OPENSSL_NATIVE)
    {
        /* pass the message itself to the backend */
        sctx->sigalg.op = "DigestSign";
        return xkey_sign_dispatch(ctx, sig, siglen, tbs, tbslen);
    }

    /* create digest and pass on to signature_sign() */

    const char *mdname = sctx->sigalg.mdname;
    EVP_MD *md = EVP_MD_fetch(sctx->prov->libctx, mdname, NULL);
    if (!md)
    {
        msg(M_WARN, "WARN: xkey digest_sign_init: MD_fetch failed for <%s>", mdname);
        return 0;
    }

    /* construct digest using OpenSSL */
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int sz;
    if (EVP_Digest(tbs, tbslen, buf, &sz, md, NULL) != 1)
    {
        msg(M_WARN, "WARN: xkey digest_sign: EVP_Digest failed");
        EVP_MD_free(md);
        return 0;
    }
    EVP_MD_free(md);

    return signature_sign(ctx, sig, siglen, sigsize, buf, sz);
}

/* Sign digest using native sign function -- will only work for native keys
 */
int
xkey_native_sign(XKEY_KEYDATA *key, unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen, XKEY_SIGALG sigalg)
{
    xkey_dmsg(D_XKEY, "entry");

    ASSERT(key);

    EVP_PKEY *pkey = key->handle;
    int ret = 0;

    ASSERT(sig);

    if (!pkey)
    {
        msg(M_NONFATAL, "Error: xkey provider: signature request with empty private key");
        return 0;
    }

    const char *saltlen = sigalg.saltlen;
    const char *mdname = sigalg.mdname;
    const char *padmode = sigalg.padmode;

    xkey_dmsg(D_XKEY, "digest=<%s>, padmode=<%s>, saltlen=<%s>", mdname, padmode, saltlen);

    int i = 0;
    OSSL_PARAM params[6];
    if (EVP_PKEY_get_id(pkey) == EVP_PKEY_RSA)
    {
        params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, (char *)mdname, 0);
        params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, (char *)padmode, 0);
        if (!strcmp(sigalg.padmode, "pss"))
        {
            params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, (char *) saltlen, 0);
            /* same digest for mgf1 */
            params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, (char *) mdname, 0);
        }
    }
    params[i++] = OSSL_PARAM_construct_end();

    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new_from_pkey(key->prov->libctx, pkey, NULL);

    if (!ectx)
    {
        msg(M_WARN, "WARN: xkey test_sign: call to EVP_PKEY_CTX_new...failed");
        return 0;
    }

    if (EVP_PKEY_sign_init_ex(ectx, NULL) != 1)
    {
        msg(M_WARN, "WARN: xkey test_sign: call to EVP_PKEY_sign_init failed");
        return 0;
    }
    EVP_PKEY_CTX_set_params(ectx, params);

    ret = EVP_PKEY_sign(ectx, sig, siglen, tbs, tbslen);
    EVP_PKEY_CTX_free(ectx);

    return ret;
}

static const OSSL_DISPATCH signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))signature_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))signature_freectx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))signature_sign_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))signature_sign},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))signature_digest_verify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))signature_digest_verify},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))signature_digest_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))signature_digest_sign},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))signature_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))signature_settable_ctx_params},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))signature_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))signature_gettable_ctx_params},
    {0, NULL }
};

const OSSL_ALGORITHM signatures[] = {
    {"RSA:rsaEncryption", XKEY_PROV_PROPS, signature_functions, "OpenVPN xkey RSA Signature"},
    {"ECDSA", XKEY_PROV_PROPS, signature_functions, "OpenVPN xkey ECDSA Signature"},
    {"ED448", XKEY_PROV_PROPS, signature_functions, "OpenVPN xkey Ed448 Signature"},
    {"ED25519", XKEY_PROV_PROPS, signature_functions, "OpenVPN xkey Ed25519 Signature"},
    {NULL, NULL, NULL, NULL}
};

/* main provider interface */

/* provider callbacks we implement */
static OSSL_FUNC_provider_query_operation_fn query_operation;
static OSSL_FUNC_provider_gettable_params_fn gettable_params;
static OSSL_FUNC_provider_get_params_fn get_params;
static OSSL_FUNC_provider_teardown_fn teardown;

static const OSSL_ALGORITHM *
query_operation(void *provctx, int op, int *no_store)
{
    xkey_dmsg(D_XKEY, "op = %d", op);

    *no_store = 0;

    switch (op)
    {
        case OSSL_OP_SIGNATURE:
            return signatures;

        case OSSL_OP_KEYMGMT:
            return keymgmts;

        default:
            xkey_dmsg(D_XKEY, "op not supported");
            break;
    }
    return NULL;
}

static const OSSL_PARAM *
gettable_params(void *provctx)
{
    xkey_dmsg(D_XKEY, "entry");

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

    xkey_dmsg(D_XKEY, "entry");

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
    xkey_dmsg(D_XKEY, "entry");

    XKEY_PROVIDER_CTX *prov = provctx;
    if (prov && prov->libctx)
    {
        OSSL_LIB_CTX_free(prov->libctx);
    }
    OPENSSL_free(prov);
}

static const OSSL_DISPATCH dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))query_operation},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))teardown},
    {0, NULL}
};

int
xkey_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                   const OSSL_DISPATCH **out, void **provctx)
{
    XKEY_PROVIDER_CTX *prov;

    xkey_dmsg(D_XKEY, "entry");

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
