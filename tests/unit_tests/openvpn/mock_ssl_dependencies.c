/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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

/* Minimal set of mocked function/globals to get unit tests to
 * compile that use the ssl_* files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <setjmp.h>
#include <cmocka.h>


#include "ssl.h"
#include "ssl_verify.h"

int
parse_line(const char *line, char **p, const int n, const char *file,
           const int line_num, int msglevel, struct gc_arena *gc)
{
    /* Dummy function to get the linker happy, should never be called */
    assert_true(false);
    return 0;
}


int
pem_password_callback(char *buf, int size, int rwflag, void *u)
{
    return 0;
}

void
cert_hash_remember(struct tls_session *session, const int cert_depth,
                   const struct buffer *cert_hash)
{
    assert_false(true);
}

result_t
verify_cert(struct tls_session *session, openvpn_x509_cert_t *cert, int cert_depth)
{
    return FAILURE;
}
