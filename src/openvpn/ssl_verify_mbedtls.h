/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
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
 * @file Control Channel Verification Module mbed TLS backend
 */

#ifndef SSL_VERIFY_MBEDTLS_H_
#define SSL_VERIFY_MBEDTLS_H_

#include "syshead.h"
#include <mbedtls/x509_crt.h>

#ifndef __OPENVPN_X509_CERT_T_DECLARED
#define __OPENVPN_X509_CERT_T_DECLARED
typedef mbedtls_x509_crt openvpn_x509_cert_t;
#endif

/** @name Function for authenticating a new connection from a remote OpenVPN peer
 *  @{ */

/**
 * Verify that the remote OpenVPN peer's certificate allows setting up a
 * VPN tunnel.
 * @ingroup control_tls
 *
 * This callback function is called when a new TLS session is being setup to
 * determine whether the remote OpenVPN peer's certificate is allowed to
 * connect. It is called for once for every certificate in the chain. The
 * callback functionality is configured in the \c key_state_ssl_init() function,
 * which calls the mbed TLS library's \c mbedtls_ssl_conf_verify() function with
 * \c verify_callback() as its callback argument.
 *
 * It checks *flags and registers the certificate hash. If these steps succeed,
 * it calls the \c verify_cert() function, which performs OpenVPN-specific
 * verification.
 *
 * @param session_obj  - The OpenVPN \c tls_session associated with this object,
 *                       as set during SSL session setup.
 * @param cert         - The certificate used by mbed TLS.
 * @param cert_depth   - The depth of the current certificate in the chain, with
 *                       0 being the actual certificate.
 * @param flags        - Whether the remote OpenVPN peer's certificate
 *                       passed verification.  A value of 0 means it
 *                       verified successfully, any other value means it
 *                       failed. \c verify_callback() is considered to have
 *                       ok'ed this certificate if flags is 0 when it returns.
 *
 * @return The return value is 0 unless a fatal error occurred.
 */
int verify_callback(void *session_obj, mbedtls_x509_crt *cert, int cert_depth,
                    uint32_t *flags);

/** @} name Function for authenticating a new connection from a remote OpenVPN peer */

#endif /* SSL_VERIFY_MBEDTLS_H_ */
