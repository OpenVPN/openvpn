/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2021-2021 Arne Schwabe <arne@rfc2549.org>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "ssl_util.h"

static void
test_compat_lzo_string(void **state)
{
    struct gc_arena gc = gc_new();

    const char* input = "V4,dev-type tun,link-mtu 1457,tun-mtu 1400,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-server";

    const char* output = options_string_compat_lzo(input, &gc);

    assert_string_equal(output, "V4,dev-type tun,link-mtu 1458,tun-mtu 1400,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-server,comp-lzo");

    /* This string is has a much too small link-mtu so we should fail on it" */
    input = "V4,dev-type tun,link-mtu 2,tun-mtu 1400,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-server";

    output = options_string_compat_lzo(input, &gc);

    assert_string_equal(input, output);

    /* not matching at all */
    input = "V4,dev-type tun";
    output = options_string_compat_lzo(input, &gc);

    assert_string_equal(input, output);


    input = "V4,dev-type tun,link-mtu 999,tun-mtu 1400,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-server";
    output = options_string_compat_lzo(input, &gc);

    /* 999 -> 1000, 3 to 4 chars */
    assert_string_equal(output, "V4,dev-type tun,link-mtu 1000,tun-mtu 1400,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-server,comp-lzo");

    gc_free(&gc);
};

const struct CMUnitTest misc_tests[] = {
    cmocka_unit_test(test_compat_lzo_string),
};

int
main(void)
{
    return cmocka_run_group_tests(misc_tests, NULL, NULL);
}
