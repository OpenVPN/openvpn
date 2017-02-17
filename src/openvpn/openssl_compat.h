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

#endif /* OPENSSL_COMPAT_H_ */
