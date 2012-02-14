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
 * @file PKCS #11 SSL library-specific backend
 */

#ifndef PKCS11_BACKEND_H_
#define PKCS11_BACKEND_H_

#include "syshead.h"

#if defined(ENABLE_PKCS11)

#include "ssl_common.h"

#include <pkcs11-helper-1.0/pkcs11h-certificate.h>

/**
 * Retrieve PKCS #11 Certificate's DN in a printable format.
 *
 * @param certificate 	The PKCS #11 helper certificate object
 * @param gc		Garbage collection pool to allocate memory in
 *
 * @return 		Certificate's DN on success, NULL on failure
 */
char * pkcs11_certificate_dn (pkcs11h_certificate_t certificate, struct gc_arena *gc);

/**
 * Retrieve PKCS #11 Certificate's serial number in a printable format.
 *
 * @param certificate 	The PKCS #11 helper certificate object
 * @param serial	Buffer that the certificate's serial will be placed in.
 * @param serial_len	Size of said buffer.
 *
 * @return 		1 on failure, 0 on success
 */
int pkcs11_certificate_serial (pkcs11h_certificate_t certificate, char *serial,
    size_t serial_len);

/**
 * Load PKCS #11 Certificate's information into the given TLS context
 *
 * @param certificate 	The PKCS #11 helper certificate object
 * @param ssl_ctx	TLS context to use.
 *
 * @return 		1 on failure, 0 on success
 */
int pkcs11_init_tls_session(pkcs11h_certificate_t certificate,
    struct tls_root_ctx * const ssl_ctx);

#endif /* defined(ENABLE_PKCS11) */
#endif /* PKCS11_BACKEND_H_ */
