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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
        free(meth->name);
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

/* SSLeay symbols have been renamed in OpenSSL 1.1 */
#if !defined(RSA_F_RSA_OSSL_PRIVATE_ENCRYPT)
#define RSA_F_RSA_OSSL_PRIVATE_ENCRYPT       RSA_F_RSA_EAY_PRIVATE_ENCRYPT
#endif

#endif /* OPENSSL_COMPAT_H_ */
