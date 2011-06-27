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
 * @file Control Channel SSL library backend module
 */


#ifndef SSL_BACKEND_H_
#define SSL_BACKEND_H_

#include "buffer.h"

#ifdef USE_OPENSSL
#include "ssl_openssl.h"
#endif


/*
 *
 * Functions implemented in ssl.c for use by the backend SSL library
 *
 */
/*
 *
 * Functions used in ssl.c which must be implemented by the backend SSL library
 *
 */

/**
 * Perform any static initialisation necessary by the library.
 * Called on OpenVPN initialisation
 */
void tls_init_lib();

/**
 * Free any global SSL library-specific data structures.
 */
void tls_free_lib();
/**
 * Clear the underlying SSL library's error state.
 */
void tls_clear_error();

/*
 * Show the TLS ciphers that are available for us to use in the OpenSSL
 * library.
 */
void show_available_tls_ciphers ();

/*
 * The OpenSSL library has a notion of preference in TLS ciphers.  Higher
 * preference == more secure. Return the highest preference cipher.
 */
void get_highest_preference_tls_cipher (char *buf, int size);

#endif /* SSL_BACKEND_H_ */
