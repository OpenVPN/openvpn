/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
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

#include "test_common.h"

#include "route.h"
#include "networking.h"

#include "test_route.h"

/* Stubs for functions route.c references but that no test here reaches.
 * They assert rather than return quietly, so a test straying onto one
 * fails loudly instead of silently doing nothing.
 */
struct argv
argv_new(void)
{
    assert_true(0);
    struct argv a = { 0 };
    return a;
}

void
argv_free(struct argv *a)
{
    assert_true(0);
}

bool
get_ipv6_addr(const char *prefix_str, struct in6_addr *network, unsigned int *netbits,
              msglvl_t msglevel)
{
    assert_true(0);
    return false;
}

in_addr_t
getaddr(unsigned int flags, const char *hostname, int resolve_retry, bool *succeeded,
        struct signal_info *sig_info)
{
    assert_true(0);
    return 0;
}

int
openvpn_getaddrinfo(unsigned int flags, const char *hostname, const char *servname,
                    int resolve_retry_seconds, struct signal_info *sig_info, int ai_family,
                    struct addrinfo **res)
{
    assert_true(0);
    return 0;
}

struct signal_info siginfo_static; /* GLOBAL */

int
signal_reset(struct signal_info *si, int signum)
{
    assert_true(0);
    return 0;
}

static void
test_is_special_addr(void **state)
{
    assert_true(is_special_addr("net_gateway"));
    assert_true(is_special_addr("vpn_gateway"));
    assert_true(is_special_addr("remote_host"));

    assert_false(is_special_addr("10.0.0.1"));
    assert_false(is_special_addr("default"));
    assert_false(is_special_addr(NULL));
}

static void
test_netmask_to_netbits(void **state)
{
    int netbits;

    assert_true(netmask_to_netbits(0x0a000000, 0xff000000, &netbits)); /* 10/8 */
    assert_int_equal(netbits, 8);

    assert_true(netmask_to_netbits(0xc0a80100, 0xffffff00, &netbits)); /* 192.168.1/24 */
    assert_int_equal(netbits, 24);

    assert_true(netmask_to_netbits(0x00000000, 0x00000000, &netbits)); /* default route */
    assert_int_equal(netbits, 0);

    /* a full-length mask reports -1 rather than 32 */
    assert_true(netmask_to_netbits(0x0a010203, 0xffffffff, &netbits));
    assert_int_equal(netbits, -1);

    /* host bits set in the network part */
    assert_false(netmask_to_netbits(0x0a000001, 0xff000000, &netbits));

    /* not a contiguous netmask */
    assert_false(netmask_to_netbits(0x0a000000, 0xff00ff00, &netbits));
}

static void
test_netmask_to_netbits2(void **state)
{
    assert_int_equal(netmask_to_netbits2(0xff000000), 8);
    assert_int_equal(netmask_to_netbits2(0xffffff00), 24);
    assert_int_equal(netmask_to_netbits2(0x00000000), 0);

    /* unlike netmask_to_netbits(), this one reports a full-length mask as 32 */
    assert_int_equal(netmask_to_netbits2(0xffffffff), 32);

    assert_int_equal(netmask_to_netbits2(0xff00ff00), -1);
}

static void
assert_clear_host_bits(const char *addr, unsigned int netbits, const char *expected)
{
    struct route_ipv6 r6;
    struct in6_addr want;

    CLEAR(r6);
    assert_int_equal(inet_pton(AF_INET6, addr, &r6.network), 1);
    assert_int_equal(inet_pton(AF_INET6, expected, &want), 1);
    r6.netbits = netbits;

    route_ipv6_clear_host_bits(&r6);
    assert_memory_equal(&r6.network, &want, sizeof(struct in6_addr));
}

static void
test_route_ipv6_clear_host_bits(void **state)
{
    /* whole bytes cleared */
    assert_clear_host_bits("2001:db8::1", 64, "2001:db8::");
    assert_clear_host_bits("2001:db8:dead:beef::1", 32, "2001:db8::");

    /* a prefix that does not fall on a byte boundary */
    assert_clear_host_bits("2001:db8:0:00ff::1", 60, "2001:db8:0:00f0::");
    assert_clear_host_bits("2001:db8::ffff", 121, "2001:db8::ff80");

    /* nothing to clear, and everything to clear */
    assert_clear_host_bits("2001:db8::1", 128, "2001:db8::1");
    assert_clear_host_bits("2001:db8::1", 0, "::");
}

static const struct CMUnitTest route_test_list[] = {
    cmocka_unit_test(test_is_special_addr),
    cmocka_unit_test(test_netmask_to_netbits),
    cmocka_unit_test(test_netmask_to_netbits2),
    cmocka_unit_test(test_route_ipv6_clear_host_bits),
};

int
route_tests(void)
{
    openvpn_unit_test_setup();
    return cmocka_run_group_tests(route_test_list, NULL, NULL);
}
