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
 * @file Control Channel OpenSSL Backend
 */

#ifndef SSL_OPENSSL_H_
#define SSL_OPENSSL_H_

#include <openssl/ssl.h>

/**
 * SSL_OP_NO_TICKET tells OpenSSL to disable "stateless session resumption",
 * as this is something we do not want nor need, but could potentially be
 * used for a future attack.  For compatibility reasons, in the 2.3.x
 * series, we keep building if the OpenSSL version is too old to support
 * this.  2.4 requires it and will fail configure if not present.
 */
#ifndef SSL_OP_NO_TICKET
# define SSL_OP_NO_TICKET 0
#endif


/**
 * Structure that wraps the TLS context. Contents differ depending on the
 * SSL library used.
 */
struct tls_root_ctx {
    SSL_CTX *ctx;
};

struct key_state_ssl {
    SSL *ssl;			/* SSL object -- new obj created for each new key */
    BIO *ssl_bio;			/* read/write plaintext from here */
    BIO *ct_in;			/* write ciphertext to here */
    BIO *ct_out;			/* read ciphertext from here */
};

/**
 * Allocate space in SSL objects in which to store a struct tls_session
 * pointer back to parent.
 */
extern int mydata_index; /* GLOBAL */

void openssl_set_mydata_index (void);

#endif /* SSL_OPENSSL_H_ */
