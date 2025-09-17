/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2021-2025 Arne Schwabe <arne@rfc2549.org>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "socket.h"
#include "win32.h"

/* stubs for some unused functions instead of pulling in too many dependencies */
struct signal_info siginfo_static; /* GLOBAL */

int
signal_reset(struct signal_info *si, int signum)
{
    assert_true(0);
    return 0;
}

#ifdef _WIN32
struct win32_signal win32_signal; /* GLOBAL */

int
win32_signal_get(struct win32_signal *ws)
{
    assert_true(0);
    return 0;
}
#endif

int
parse_line(const char *line, char **p, const int n, const char *file, const int line_num,
           msglvl_t msglevel, struct gc_arena *gc)
{
    assert_true(0);
    return 0;
}

static void
test_add_in6_addr_tc(const char *orig_str, uint32_t add, const char *expect_str)
{
    struct in6_addr orig, result, expected;
    struct gc_arena gc = gc_new();
    assert_int_equal(inet_pton(AF_INET6, orig_str, &orig), 1);
    assert_int_equal(inet_pton(AF_INET6, expect_str, &expected), 1);
    result = add_in6_addr(orig, add);
    const char *result_str = print_in6_addr(result, 0, &gc);
    assert_string_equal(result_str, expect_str);
    assert_memory_equal(&result, &expected, sizeof(struct in6_addr));
    gc_free(&gc);
}

static bool
check_mapped_ipv4_address(void)
{
    struct gc_arena gc = gc_new();
    const char *ipv4_output = "::255.255.255.255";
    struct in6_addr addr;
    assert_int_equal(inet_pton(AF_INET6, ipv4_output, &addr), 1);
    const char *test_output = print_in6_addr(addr, 0, &gc);
    bool ret = strcmp(test_output, ipv4_output) == 0;
    gc_free(&gc);
    return ret;
}

static void
test_add_in6_addr(void **state)
{
    /* Note that some of the result strings need to account for
       print_in6_addr formatting the addresses potentially as IPv4 */
    bool mapped_ipv4 = check_mapped_ipv4_address();
    test_add_in6_addr_tc("::", 1, "::1");
    test_add_in6_addr_tc("::ff", 1, "::100");
    test_add_in6_addr_tc("::ffff", 1, mapped_ipv4 ? "::0.1.0.0" : "::1:0");
    test_add_in6_addr_tc("ffff::ffff", 1, "ffff::1:0");
    test_add_in6_addr_tc("::ffff:ffff", 1, "::1:0:0");
    test_add_in6_addr_tc("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 1, "::");
    test_add_in6_addr_tc("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 2, "::1");

    test_add_in6_addr_tc("::", UINT32_MAX, mapped_ipv4 ? "::255.255.255.255" : "::ffff:ffff");
    test_add_in6_addr_tc("::1", UINT32_MAX, "::1:0:0");
    test_add_in6_addr_tc("::ffff", UINT32_MAX, "::1:0:fffe");
    test_add_in6_addr_tc("ffff::ffff", UINT32_MAX, "ffff::1:0:fffe");
    test_add_in6_addr_tc("::ffff:ffff", UINT32_MAX, "::1:ffff:fffe");
    test_add_in6_addr_tc("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", UINT32_MAX,
                         mapped_ipv4 ? "::255.255.255.254" : "::ffff:fffe");
}

const struct CMUnitTest socket_tests[] = {
    cmocka_unit_test(test_add_in6_addr)
};

int
main(void)
{
    return cmocka_run_group_tests(socket_tests, NULL, NULL);
}
