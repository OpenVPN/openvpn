/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2025 Frank Lichtenheld <frank@lichtenheld.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by the
 *  Free Software Foundation, either version 2 of the License,
 *  or (at your option) any later version.
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

#include <setjmp.h>
#include <cmocka.h>
#include "test_common.h"

#include <winsock2.h>
#include <windows.h>

#include "interactive.c"

BOOL
ReportStatusToSCMgr(SERVICE_STATUS_HANDLE service, SERVICE_STATUS *status)
{
    return TRUE;
}

static void
test_list_contains_domain(void **state)
{
    PCWSTR domain = L"openvpn.net";
    size_t domain_len = wcslen(domain);
    assert_true(ListContainsDomain(domain, domain, domain_len));
    assert_true(ListContainsDomain(L"openvpn.com,openvpn.net", domain, domain_len));
    assert_true(ListContainsDomain(L"openvpn.net,openvpn.com", domain, domain_len));

    assert_false(ListContainsDomain(L"openvpn.com", domain, domain_len));
    assert_false(ListContainsDomain(L"internal.openvpn.net", domain, domain_len));
}

#define BUF_SIZE 64
static void
test_convert_itf_dns_domains(void **state)
{
    DWORD size, orig_size, len, res_len;
    LSTATUS err;
    const DWORD glyph_size = sizeof(wchar_t);

    wchar_t domains_1[BUF_SIZE] = L"openvpn.com";
    len = (DWORD)wcslen(domains_1) + 1;
    size = orig_size = len * glyph_size;
    wchar_t domains_1_res[BUF_SIZE] = L".openvpn.com";
    res_len = len + 2; /* adds . and \0 */
    err = ConvertItfDnsDomains(L"openvpn.net", domains_1, &size, BUF_SIZE);
    assert_memory_equal(domains_1, domains_1_res, size);
    assert_int_equal(size, res_len * glyph_size);
    assert_int_equal(err, NO_ERROR);

    wchar_t domains_2[BUF_SIZE] = L"openvpn.com,openvpn.net";
    len = (DWORD)wcslen(domains_2) + 1;
    size = orig_size = len * glyph_size;
    wchar_t domains_2_res[BUF_SIZE] = L".openvpn.com";
    res_len = (DWORD)wcslen(domains_2_res) + 2;
    err = ConvertItfDnsDomains(L"openvpn.net", domains_2, &size, BUF_SIZE);
    assert_memory_equal(domains_2, domains_2_res, size);
    assert_int_equal(size, res_len * glyph_size);
    assert_int_equal(err, NO_ERROR);

    wchar_t domains_3[BUF_SIZE] = L"openvpn.com,openvpn.net";
    len = (DWORD)wcslen(domains_3) + 1;
    size = orig_size = len * glyph_size;
    wchar_t domains_3_res[BUF_SIZE] = L".openvpn.net";
    res_len = (DWORD)wcslen(domains_3_res) + 2;
    err = ConvertItfDnsDomains(L"openvpn.com", domains_3, &size, BUF_SIZE);
    assert_memory_equal(domains_3, domains_3_res, size);
    assert_int_equal(size, res_len * glyph_size);
    assert_int_equal(err, NO_ERROR);

    wchar_t domains_4[BUF_SIZE] = L"openvpn.com,openvpn.net";
    len = (DWORD)wcslen(domains_4) + 1;
    size = orig_size = len * glyph_size;
    wchar_t domains_4_res[BUF_SIZE] = L".openvpn.com\0.openvpn.net";
    res_len = len + 3; /* adds two . and one \0 */
    err = ConvertItfDnsDomains(NULL, domains_4, &size, BUF_SIZE);
    assert_memory_equal(domains_4, domains_4_res, size);
    assert_int_equal(size, res_len * glyph_size);
    assert_int_equal(err, NO_ERROR);
}

int
wmain(void)
{
    openvpn_unit_test_setup();
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_list_contains_domain),
        cmocka_unit_test(test_convert_itf_dns_domains),
    };

    int ret = cmocka_run_group_tests_name("openvpnserv tests", tests, NULL, NULL);

    return ret;
}
