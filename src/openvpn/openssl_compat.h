/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2010-2017 Fox Crypto B.V. <openvpn@fox-it.com>
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

/**
 * @file OpenSSL compatibility stub
 *
 * This file provide compatibility stubs for the OpenSSL libraries
 * prior to version 1.1. This version introduces many changes in the
 * library interface, including the fact that various objects and
 * structures are not fully opaque.
 */

#ifndef OPENSSL_COMPAT_H_
#define OPENSSL_COMPAT_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "buffer.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>

#if !defined(HAVE_EVP_MD_CTX_RESET)
/**
 * Reset a message digest context
 *
 * @param ctx                 The message digest context
 * @return                    1 on success, 0 on error
 */
static inline int
EVP_MD_CTX_reset(EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_cleanup(ctx);
    return 1;
}
#endif

#if !defined(HAVE_EVP_MD_CTX_FREE)
/**
 * Free an existing message digest context
 *
 * @param ctx                 The message digest context
 */
static inline void
EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    free(ctx);
}
#endif

#if !defined(HAVE_EVP_MD_CTX_NEW)
/**
 * Allocate a new message digest object
 *
 * @return                    A zero'ed message digest object
 */
static inline EVP_MD_CTX *
EVP_MD_CTX_new(void)
{
    EVP_MD_CTX *ctx = NULL;
    ALLOC_OBJ_CLEAR(ctx, EVP_MD_CTX);
    return ctx;
}
#endif

#if !defined(HAVE_HMAC_CTX_RESET)
/**
 * Reset a HMAC context
 *
 * OpenSSL 1.1+ removes APIs HMAC_CTX_init() and HMAC_CTX_cleanup()
 * and replace them with a single call that does a cleanup followed
 * by an init. A proper _reset() for OpenSSL < 1.1 should perform
 * a similar set of operations.
 *
 * It means that before we kill a HMAC context, we'll have to cleanup
 * again, as we probably have allocated a few resources when we forced
 * an init.
 *
 * @param ctx                 The HMAC context
 * @return                    1 on success, 0 on error
 */
static inline int
HMAC_CTX_reset(HMAC_CTX *ctx)
{
    HMAC_CTX_cleanup(ctx);
    HMAC_CTX_init(ctx);
    return 1;
}
#endif

#if !defined(HAVE_HMAC_CTX_FREE)
/**
 * Cleanup and free an existing HMAC context
 *
 * @param ctx                 The HMAC context
 */
static inline void
HMAC_CTX_free(HMAC_CTX *ctx)
{
    HMAC_CTX_cleanup(ctx);
    free(ctx);
}
#endif

#if !defined(HAVE_HMAC_CTX_NEW)
/**
 * Allocate a new HMAC context object
 *
 * @return                    A zero'ed HMAC context object
 */
static inline HMAC_CTX *
HMAC_CTX_new(void)
{
    HMAC_CTX *ctx = NULL;
    ALLOC_OBJ_CLEAR(ctx, HMAC_CTX);
    return ctx;
}
#endif

#if !defined(HAVE_SSL_CTX_GET_DEFAULT_PASSWD_CB_USERDATA)
/**
 * Fetch the default password callback user data from the SSL context
 *
 * @param ctx                SSL context
 * @return                   The password callback user data
 */
static inline void *
SSL_CTX_get_default_passwd_cb_userdata(SSL_CTX *ctx)
{
    return ctx ? ctx->default_passwd_callback_userdata : NULL;
}
#endif

#if !defined(HAVE_SSL_CTX_GET_DEFAULT_PASSWD_CB)
/**
 * Fetch the default password callback from the SSL context
 *
 * @param ctx                SSL context
 * @return                   The password callback
 */
static inline pem_password_cb *
SSL_CTX_get_default_passwd_cb(SSL_CTX *ctx)
{
    return ctx ? ctx->default_passwd_callback : NULL;
}
#endif

#if !defined(HAVE_X509_GET0_PUBKEY)
/**
 * Get the public key from a X509 certificate
 *
 * @param x                  X509 certificate
 * @return                   The certificate public key
 */
static inline EVP_PKEY *
X509_get0_pubkey(const X509 *x)
{
    return (x && x->cert_info && x->cert_info->key) ?
           x->cert_info->key->pkey : NULL;
}
#endif

#if !defined(HAVE_X509_STORE_GET0_OBJECTS)
/**
 * Fetch the X509 object stack from the X509 store
 *
 * @param store              X509 object store
 * @return                   the X509 object stack
 */
static inline STACK_OF(X509_OBJECT) *
X509_STORE_get0_objects(X509_STORE *store)
{
    return store ? store->objs : NULL;
}
#endif

#if !defined(HAVE_X509_OBJECT_FREE)
/**
 * Destroy a X509 object
 *
 * @param obj                X509 object
 */
static inline void
X509_OBJECT_free(X509_OBJECT *obj)
{
    if (obj)
    {
        X509_OBJECT_free_contents(obj);
        OPENSSL_free(obj);
    }
}
#endif

#if !defined(HAVE_X509_OBJECT_GET_TYPE)
/**
 * Get the type of an X509 object
 *
 * @param obj                X509 object
 * @return                   The underlying object type
 */
static inline int
X509_OBJECT_get_type(const X509_OBJECT *obj)
{
    return obj ? obj->type : X509_LU_FAIL;
}
#endif

#if !defined(HAVE_EVP_PKEY_GET0_RSA)
/**
 * Get the RSA object of a public key
 *
 * @param pkey                Public key object
 * @return                    The underlying RSA object
 */
static inline RSA *
EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
{
    return pkey ? pkey->pkey.rsa : NULL;
}
#endif

#if !defined(HAVE_EVP_PKEY_GET0_EC_KEY) && !defined(OPENSSL_NO_EC)
/**
 * Get the EC_KEY object of a public key
 *
 * @param pkey                Public key object
 * @return                    The underlying EC_KEY object
 */
static inline EC_KEY *
EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey)
{
    return pkey ? pkey->pkey.ec : NULL;
}
#endif

#if !defined(HAVE_EVP_PKEY_ID)
/**
 * Get the PKEY type
 *
 * @param pkey                Public key object
 * @return                    The key type
 */
static inline int
EVP_PKEY_id(const EVP_PKEY *pkey)
{
    return pkey ? pkey->type : EVP_PKEY_NONE;
}
#endif

#if !defined(HAVE_EVP_PKEY_GET0_DSA)
/**
 * Get the DSA object of a public key
 *
 * @param pkey                Public key object
 * @return                    The underlying DSA object
 */
static inline DSA *
EVP_PKEY_get0_DSA(EVP_PKEY *pkey)
{
    return pkey ? pkey->pkey.dsa : NULL;
}
#endif

#if !defined(HAVE_RSA_SET_FLAGS)
/**
 * Set the RSA flags
 *
 * @param rsa                 The RSA object
 * @param flags               New flags value
 */
static inline void
RSA_set_flags(RSA *rsa, int flags)
{
    if (rsa)
    {
        rsa->flags = flags;
    }
}
#endif

#if !defined(HAVE_RSA_GET0_KEY)
/**
 * Get the RSA parameters
 *
 * @param rsa                 The RSA object
 * @param n                   The @c n parameter
 * @param e                   The @c e parameter
 * @param d                   The @c d parameter
 */
static inline void
RSA_get0_key(const RSA *rsa, const BIGNUM **n,
             const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
    {
        *n = rsa ? rsa->n : NULL;
    }
    if (e != NULL)
    {
        *e = rsa ? rsa->e : NULL;
    }
    if (d != NULL)
    {
        *d = rsa ? rsa->d : NULL;
    }
}
#endif

#if !defined(HAVE_RSA_SET0_KEY)
/**
 * Set the RSA parameters
 *
 * @param rsa                 The RSA object
 * @param n                   The @c n parameter
 * @param e                   The @c e parameter
 * @param d                   The @c d parameter
 * @return                    1 on success, 0 on error
 */
static inline int
RSA_set0_key(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    if ((rsa->n == NULL && n == NULL)
        || (rsa->e == NULL && e == NULL))
    {
        return 0;
    }

    if (n != NULL)
    {
        BN_free(rsa->n);
        rsa->n = n;
    }
    if (e != NULL)
    {
        BN_free(rsa->e);
        rsa->e = e;
    }
    if (d != NULL)
    {
        BN_free(rsa->d);
        rsa->d = d;
    }

    return 1;
}
#endif

#if !defined(HAVE_RSA_BITS)
/**
 * Number of significant RSA bits
 *
 * @param rsa                The RSA object ; shall not be NULL
 * @return                   The number of RSA bits or 0 on error
 */
static inline int
RSA_bits(const RSA *rsa)
{
    const BIGNUM *n = NULL;
    RSA_get0_key(rsa, &n, NULL, NULL);
    return n ? BN_num_bits(n) : 0;
}
#endif

#if !defined(HAVE_DSA_GET0_PQG)
/**
 * Get the DSA parameters
 *
 * @param dsa                 The DSA object
 * @param p                   The @c p parameter
 * @param q                   The @c q parameter
 * @param g                   The @c g parameter
 */
static inline void
DSA_get0_pqg(const DSA *dsa, const BIGNUM **p,
             const BIGNUM **q, const BIGNUM **g)
{
    if (p != NULL)
    {
        *p = dsa ? dsa->p : NULL;
    }
    if (q != NULL)
    {
        *q = dsa ? dsa->q : NULL;
    }
    if (g != NULL)
    {
        *g = dsa ? dsa->g : NULL;
    }
}
#endif

#if !defined(HAVE_DSA_BITS)
/**
 * Number of significant DSA bits
 *
 * @param rsa                The DSA object ; shall not be NULL
 * @return                   The number of DSA bits or 0 on error
 */
static inline int
DSA_bits(const DSA *dsa)
{
    const BIGNUM *p = NULL;
    DSA_get0_pqg(dsa, &p, NULL, NULL);
    return p ? BN_num_bits(p) : 0;
}
#endif

#if !defined(HAVE_RSA_METH_NEW)
/**
 * Allocate a new RSA method object
 *
 * @param name               The object name
 * @param flags              Configuration flags
 * @return                   A new RSA method object
 */
static inline RSA_METHOD *
RSA_meth_new(const char *name, int flags)
{
    RSA_METHOD *rsa_meth = NULL;
    ALLOC_OBJ_CLEAR(rsa_meth, RSA_METHOD);
    rsa_meth->name = string_alloc(name, NULL);
    rsa_meth->flags = flags;
    return rsa_meth;
}
#endif

#if !defined(HAVE_RSA_METH_FREE)
/**
 * Free an existing RSA_METHOD object
 *
 * @param meth               The RSA_METHOD object
 */
static inline void
RSA_meth_free(RSA_METHOD *meth)
{
    if (meth)
    {
        /* OpenSSL defines meth->name to be a const pointer, yet we
         * feed it with an allocated string (from RSA_meth_new()).
         * Thus we are allowed to free it here. In order to avoid a
         * "passing 'const char *' to parameter of type 'void *' discards
         * qualifiers" warning, we force the pointer to be a non-const value.
         */
        free((char *)meth->name);
        free(meth);
    }
}
#endif

#if !defined(HAVE_RSA_METH_SET_PUB_ENC)
/**
 * Set the public encoding function of an RSA_METHOD object
 *
 * @param meth               The RSA_METHOD object
 * @param pub_enc            the public encoding function
 * @return                   1 on success, 0 on error
 */
static inline int
RSA_meth_set_pub_enc(RSA_METHOD *meth,
                     int (*pub_enc) (int flen, const unsigned char *from,
                                     unsigned char *to, RSA *rsa,
                                     int padding))
{
    if (meth)
    {
        meth->rsa_pub_enc = pub_enc;
        return 1;
    }
    return 0;
}
#endif

#if !defined(HAVE_RSA_METH_SET_PUB_DEC)
/**
 * Set the public decoding function of an RSA_METHOD object
 *
 * @param meth               The RSA_METHOD object
 * @param pub_dec            the public decoding function
 * @return                   1 on success, 0 on error
 */
static inline int
RSA_meth_set_pub_dec(RSA_METHOD *meth,
                     int (*pub_dec) (int flen, const unsigned char *from,
                                     unsigned char *to, RSA *rsa,
                                     int padding))
{
    if (meth)
    {
        meth->rsa_pub_dec = pub_dec;
        return 1;
    }
    return 0;
}
#endif

#if !defined(HAVE_RSA_METH_SET_PRIV_ENC)
/**
 * Set the private encoding function of an RSA_METHOD object
 *
 * @param meth               The RSA_METHOD object
 * @param priv_enc           the private encoding function
 * @return                   1 on success, 0 on error
 */
static inline int
RSA_meth_set_priv_enc(RSA_METHOD *meth,
                      int (*priv_enc) (int flen, const unsigned char *from,
                                       unsigned char *to, RSA *rsa,
                                       int padding))
{
    if (meth)
    {
        meth->rsa_priv_enc = priv_enc;
        return 1;
    }
    return 0;
}
#endif

#if !defined(HAVE_RSA_METH_SET_PRIV_DEC)
/**
 * Set the private decoding function of an RSA_METHOD object
 *
 * @param meth               The RSA_METHOD object
 * @param priv_dec           the private decoding function
 * @return                   1 on success, 0 on error
 */
static inline int
RSA_meth_set_priv_dec(RSA_METHOD *meth,
                      int (*priv_dec) (int flen, const unsigned char *from,
                                       unsigned char *to, RSA *rsa,
                                       int padding))
{
    if (meth)
    {
        meth->rsa_priv_dec = priv_dec;
        return 1;
    }
    return 0;
}
#endif

#if !defined(HAVE_RSA_METH_SET_INIT)
/**
 * Set the init function of an RSA_METHOD object
 *
 * @param meth               The RSA_METHOD object
 * @param init               the init function
 * @return                   1 on success, 0 on error
 */
static inline int
RSA_meth_set_init(RSA_METHOD *meth, int (*init) (RSA *rsa))
{
    if (meth)
    {
        meth->init = init;
        return 1;
    }
    return 0;
}
#endif

#if !defined(HAVE_RSA_METH_SET_FINISH)
/**
 * Set the finish function of an RSA_METHOD object
 *
 * @param meth               The RSA_METHOD object
 * @param finish             the finish function
 * @return                   1 on success, 0 on error
 */
static inline int
RSA_meth_set_finish(RSA_METHOD *meth, int (*finish) (RSA *rsa))
{
    if (meth)
    {
        meth->finish = finish;
        return 1;
    }
    return 0;
}
#endif

#if !defined(HAVE_RSA_METH_SET0_APP_DATA)
/**
 * Set the application data of an RSA_METHOD object
 *
 * @param meth               The RSA_METHOD object
 * @param app_data           Application data
 * @return                   1 on success, 0 on error
 */
static inline int
RSA_meth_set0_app_data(RSA_METHOD *meth, void *app_data)
{
    if (meth)
    {
        meth->app_data = app_data;
        return 1;
    }
    return 0;
}
#endif

#if !defined(HAVE_EC_GROUP_ORDER_BITS) && !defined(OPENSSL_NO_EC)
/**
 * Gets the number of bits of the order of an EC_GROUP
 *
 *  @param  group               EC_GROUP object
 *  @return                     number of bits of group order.
 */
static inline int
EC_GROUP_order_bits(const EC_GROUP *group)
{
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, NULL);
    int bits = BN_num_bits(order);
    BN_free(order);
    return bits;
}
#endif

/* SSLeay symbols have been renamed in OpenSSL 1.1 */
#if !defined(RSA_F_RSA_OSSL_PRIVATE_ENCRYPT)
#define RSA_F_RSA_OSSL_PRIVATE_ENCRYPT       RSA_F_RSA_EAY_PRIVATE_ENCRYPT
#endif

#endif /* OPENSSL_COMPAT_H_ */
