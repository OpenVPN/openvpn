/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2010 Fox Crypto B.V. <openvpn@fox-it.com>
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
 * @file Control Channel PolarSSL Backend
 */

#ifndef SSL_POLARSSL_H_
#define SSL_POLARSSL_H_

#include "syshead.h"

#include <polarssl/ssl.h>

#if defined(ENABLE_PKCS11)
#include <polarssl/pkcs11.h>
#endif

typedef struct _buffer_entry buffer_entry;

struct _buffer_entry {
    size_t length;
    uint8_t *data;
    buffer_entry *next_block;
};

typedef struct {
    size_t data_start;
    buffer_entry *first_block;
    buffer_entry *last_block;
} endless_buffer;

/**
 * Structure that wraps the TLS context. Contents differ depending on the
 * SSL library used.
 *
 * Either \c priv_key_pkcs11 or \c priv_key must be filled in.
 */
struct tls_root_ctx {
    bool initialised; 		/**< True if the context has been initialised */

    int endpoint; 		/**< Whether or not this is a server or a client */

    dhm_context *dhm_ctx;	/**< Diffie-Helmann-Merkle context */
    x509_cert *crt_chain;	/**< Local Certificate chain */
    x509_cert *ca_chain;	/**< CA chain for remote verification */
    rsa_context *priv_key;	/**< Local private key */
#if defined(ENABLE_PKCS11)
    pkcs11_context *priv_key_pkcs11;	/**< PKCS11 private key */
#endif
#ifdef MANAGMENT_EXTERNAL_KEY
    struct external_context *external_key; /**< Management external key */
#endif
    int * allowed_ciphers;	/**< List of allowed ciphers for this connection */
};

struct key_state_ssl {
        ssl_context *ctx;
        endless_buffer *ct_in;
        endless_buffer *ct_out;
};


#endif /* SSL_POLARSSL_H_ */
