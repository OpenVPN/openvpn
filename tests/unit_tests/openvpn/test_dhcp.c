/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2025-2026 OpenVPN Inc <sales@openvpn.net>
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

#include "test_common.h"
#include "mock_msg.h"

#include "dhcp.c"

uint16_t
ip_checksum(const sa_family_t af, const uint8_t *payload, const int len_payload,
            const uint8_t *src_addr, const uint8_t *dest_addr, const int proto)
{
    return 0;
}
const char *
print_in_addr_t(in_addr_t addr, unsigned int flags, struct gc_arena *gc)
{
    return "dummy";
}

static void
test_write_dhcp_search_str(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer out_buf = alloc_buf_gc(512, &gc);
    struct buffer clear_buf = alloc_buf_gc(512, &gc);
    buf_clear(&clear_buf);
    bool error = false;

#define LONGDOMAIN "a-reaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaally-long-domain"
    const char *search_list[] = {
        "openvpn.net",
        "openvpn.org",
        LONGDOMAIN,
        "subdomain." LONGDOMAIN ".top123",  /* maximum length */
        "subdomain-" LONGDOMAIN "-top123",  /* maximum length */
        "subdomain." LONGDOMAIN ".top1234", /* too long */
        "sub..tld",                         /* invalid */
    };
    const unsigned char output_1[28] = "\x77\x1a\x07openvpn\x03net\x00\x07openvpn\x03org";
    buf_clear(&out_buf);
    write_dhcp_search_str(&out_buf, DHCP_DOMAIN_SEARCH, search_list, 2, &error);
    assert_memory_equal(BPTR(&out_buf), output_1, sizeof(output_1));
    assert_false(error);

    /* buf too small */
    struct buffer small_buf = alloc_buf_gc(sizeof(output_1) - 1, &gc);
    buf_clear(&small_buf);
    write_dhcp_search_str(&small_buf, DHCP_DOMAIN_SEARCH, search_list, 2, &error);
    assert_memory_equal(BPTR(&small_buf), BPTR(&clear_buf), buf_forward_capacity_total(&small_buf));
    assert_true(error);
    error = false;

    const unsigned char output_2[0xEC + 3 + 1] = "\x77\xEE\xEC" LONGDOMAIN;
    buf_clear(&out_buf);
    write_dhcp_search_str(&out_buf, DHCP_DOMAIN_SEARCH, search_list + 2, 1, &error);
    assert_memory_equal(BPTR(&out_buf), output_2, sizeof(output_2));
    assert_false(error);

    const unsigned char output_3[0xEC + 3 + 10 + 7 + 1] = "\x77\xFF\x09subdomain\xEC" LONGDOMAIN "\x06top123";
    buf_clear(&out_buf);
    write_dhcp_search_str(&out_buf, DHCP_DOMAIN_SEARCH, search_list + 3, 1, &error);
    assert_memory_equal(BPTR(&out_buf), output_3, sizeof(output_3));
    assert_false(error);

    const unsigned char output_4[0xEC + 3 + 10 + 7 + 1] = "\x77\xFF\xFDsubdomain-" LONGDOMAIN "-top123";
    buf_clear(&out_buf);
    write_dhcp_search_str(&out_buf, DHCP_DOMAIN_SEARCH, search_list + 4, 1, &error);
    assert_memory_equal(BPTR(&out_buf), output_4, sizeof(output_4));
    assert_false(error);

    buf_clear(&out_buf);
    write_dhcp_search_str(&out_buf, DHCP_DOMAIN_SEARCH, search_list + 5, 1, &error);
    assert_memory_equal(BPTR(&out_buf), BPTR(&clear_buf), buf_forward_capacity_total(&clear_buf));
    assert_true(error);
    error = false;

    buf_clear(&out_buf);
    write_dhcp_search_str(&out_buf, DHCP_DOMAIN_SEARCH, search_list, 3, &error);
    assert_memory_equal(BPTR(&out_buf), BPTR(&clear_buf), buf_forward_capacity_total(&clear_buf));
    assert_true(error);
    error = false;

    /* FIXME: should probably throw an error instead adding that \x00 ? */
    const char output_5[12] = "\x77\x0a\x03sub\x00\x03tld";
    buf_clear(&out_buf);
    write_dhcp_search_str(&out_buf, DHCP_DOMAIN_SEARCH, search_list + 6, 1, &error);
    assert_memory_equal(BPTR(&out_buf), output_5, sizeof(output_5));
    assert_false(error);

    /* Several entries whose accumulated length lands exactly on the guard
     * boundary. Each entry consumes strlen()+2 bytes of tmp_buf (one length
     * prefix plus one trailing NUL), but the guard only accounts for
     * strlen()+1, so the last entry writes one byte past tmp_buf[256].
     * Sizes: 4 x 50 leaves len == 208, the final 47 makes
     * 47 + 208 + 1 == 256, which the guard still accepts. */
#define D50 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define D47 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    const char *overflow_list[] = { D50, D50, D50, D50, D47 };
    assert_int_equal(strlen(D50), 50);
    assert_int_equal(strlen(D47), 47);
    buf_clear(&out_buf);
    write_dhcp_search_str(&out_buf, DHCP_DOMAIN_SEARCH, overflow_list, 5, &error);
    /* total is 257 > 255, so the option must be rejected -- the point of this
     * case is that tmp_buf must not be written out of bounds on the way. */
    assert_true(error);
    error = false;

    gc_free(&gc);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_write_dhcp_search_str),
    };

    return cmocka_run_group_tests_name("dhcp", tests, NULL, NULL);
}
