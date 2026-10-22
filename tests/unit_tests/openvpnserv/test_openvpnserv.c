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
ReportStatusToSCMgr(SERVICE_STATUS_HANDLE svc_handle, SERVICE_STATUS *svc_status)
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
    assert_true(ListContainsDomain(L"openvpn.org,openvpn.net,openvpn.com", domain, domain_len));

    assert_false(ListContainsDomain(L"openvpn.com", domain, domain_len));
    assert_false(ListContainsDomain(L"internal.openvpn.net", domain, domain_len));
    assert_false(ListContainsDomain(L"openvpn.com,internal.openvpn.net", domain, domain_len));
    assert_false(ListContainsDomain(L"internal.openvpn.net,openvpn.com", domain, domain_len));
}

/*
 * Run ConvertItfDnsDomains() on a heap buffer of exactly capacity bytes,
 * so that ASAN can detect overruns, with everything after the input string
 * poisoned, so that terminators which are counted but not written show.
 */
static void
check_convert(PCWSTR search_domains, PCWSTR input, DWORD capacity,
              LSTATUS expected_err, PCWSTR expected)
{
    const DWORD glyph_size = sizeof(wchar_t);

    /* Size of the expected MULTI_SZ including both terminators, or 0 */
    DWORD expected_size = 0;
    if (expected)
    {
        PCWSTR end = expected;
        while (*end)
        {
            end += wcslen(end) + 1;
        }
        expected_size = (DWORD)(end - expected + 1) * glyph_size;
    }

    DWORD size = (DWORD)(wcslen(input) + 1) * glyph_size;
    assert_true(size <= capacity);

    wchar_t *domains = malloc(capacity);
    assert_non_null(domains);
    memset(domains, 0x41, capacity);
    memcpy(domains, input, size);

    LSTATUS err = ConvertItfDnsDomains(search_domains, domains, &size, capacity);
    assert_int_equal(err, expected_err);
    assert_int_equal(size, expected_size);
    if (expected_size)
    {
        assert_memory_equal(domains, expected, expected_size);
    }
    free(domains);
}

#define BUF_SIZE 64
static void
test_convert_itf_dns_domains(void **state)
{
    const DWORD glyph_size = sizeof(wchar_t);
    const DWORD cap = BUF_SIZE * glyph_size;

    /* Remove the domain from a single-entry list */
    check_convert(L"openvpn.com", L"openvpn.com", cap, ERROR_FILE_NOT_FOUND, NULL);

    /* Remove no domain from a single-entry list */
    check_convert(L"openvpn.net", L"openvpn.com", cap, NO_ERROR, L".openvpn.com\0");

    /* Remove the second domain from a two-entry list */
    check_convert(L"openvpn.net", L"openvpn.com,openvpn.net", cap, NO_ERROR, L".openvpn.com\0");

    /* Remove the first domain from a two-entry list */
    check_convert(L"openvpn.com", L"openvpn.com,openvpn.net", cap, NO_ERROR, L".openvpn.net\0");

    /* Remove no domain from a two-entry list */
    check_convert(NULL, L"openvpn.com,openvpn.net", cap, NO_ERROR, L".openvpn.com\0.openvpn.net\0");

    /* Remove the first domain from a three-entry list */
    check_convert(L"openvpn.com", L"openvpn.com,openvpn.net,openvpn.org", cap, NO_ERROR,
                  L".openvpn.net\0.openvpn.org\0");

    /* Remove the middle domain from a three-entry list */
    check_convert(L"openvpn.net", L"openvpn.com,openvpn.net,openvpn.org", cap, NO_ERROR,
                  L".openvpn.com\0.openvpn.org\0");

    /* Remove the last domain from a three-entry list */
    check_convert(L"openvpn.org", L"openvpn.com,openvpn.net,openvpn.org", cap, NO_ERROR,
                  L".openvpn.com\0.openvpn.net\0");

    /* Empty entries are skipped */
    check_convert(NULL, L",a.com", cap, NO_ERROR, L".a.com\0");
    check_convert(NULL, L"a.com,", cap, NO_ERROR, L".a.com\0");
    check_convert(NULL, L"a.com,,b.com", cap, NO_ERROR, L".a.com\0.b.com\0");
    check_convert(L"a.com", L",a.com,", cap, ERROR_FILE_NOT_FOUND, NULL);
    check_convert(NULL, L",,,", cap, ERROR_FILE_NOT_FOUND, NULL);
    check_convert(NULL, L"", cap, ERROR_FILE_NOT_FOUND, NULL);

    /* Size is 0 if all domains are removed */
    check_convert(L"a.com,b.com", L"b.com,a.com", cap, ERROR_FILE_NOT_FOUND, NULL);

    /* Output exactly fills the buffer: 2 * (dot + 5 + NUL) + NUL */
    check_convert(NULL, L"a.com,b.com", 15 * glyph_size, NO_ERROR, L".a.com\0.b.com\0");

    /* Remove the last domain from a four-entry list because of size constraints,
     * all four would need 3 * 13 + 28 + 1 = 68 glyphs, the buffer is one glyph short */
    check_convert(NULL, L"openvpn.com,openvpn.net,openvpn.org,am-ende-noch-eine-lange.de",
                  67 * glyph_size, ERROR_MORE_DATA, L".openvpn.com\0.openvpn.net\0.openvpn.org\0");

    /* Input fills the buffer, no space for dot and terminators */
    check_convert(NULL, L"a.com", 6 * glyph_size, ERROR_MORE_DATA, NULL);
}

static void
test_append_search_list(void **state)
{
    WCHAR list[64];

    /* append to an empty list */
    wcscpy(list, L"");
    assert_true(AppendSearchList(list, _countof(list), L"a.com"));
    assert_int_equal(wcscmp(list, L"a.com"), 0);

    /* append to a non-empty list */
    wcscpy(list, L"x.com");
    assert_true(AppendSearchList(list, _countof(list), L"a.com,b.com"));
    assert_int_equal(wcscmp(list, L"x.com,a.com,b.com"), 0);

    /* appending an empty string is a no-op */
    wcscpy(list, L"x.com");
    assert_true(AppendSearchList(list, _countof(list), L""));
    assert_int_equal(wcscmp(list, L"x.com"), 0);

    /* duplicates are allowed -- relied on by the multiset-aware remove */
    wcscpy(list, L"x.com");
    assert_true(AppendSearchList(list, _countof(list), L"x.com"));
    assert_int_equal(wcscmp(list, L"x.com,x.com"), 0);

    /* overflow: the list is left unchanged */
    WCHAR tiny[8];
    wcscpy(tiny, L"abc");
    assert_false(AppendSearchList(tiny, _countof(tiny), L"long.example.com"));
    assert_int_equal(wcscmp(tiny, L"abc"), 0);
}

static void
test_remove_search_list_tokens(void **state)
{
    WCHAR list[256];

    /* substring rejection: removing "vpn.corp.local" does NOT touch
     * "test.vpn.corp.local" -- the original wcsstr-based code did. */
    wcscpy(list, L"test.vpn.corp.local,other.com,vpn.corp.local");
    assert_int_equal(RemoveSearchListTokens(list, L"vpn.corp.local"), 1);
    assert_int_equal(wcscmp(list, L"test.vpn.corp.local,other.com"), 0);

    /* multiset semantics: one undo token removes one occurrence */
    wcscpy(list, L"corp.local,corp.local");
    assert_int_equal(RemoveSearchListTokens(list, L"corp.local"), 1);
    assert_int_equal(wcscmp(list, L"corp.local"), 0);

    /* removal targets the LAST occurrence so a pre-existing prefix is
     * preserved: with initial list "a,b" a VPN append yields "a,b,a";
     * removing "a" must restore "a,b" (not "b,a") so the result matches
     * the stored initial snapshot and a full reset can be triggered */
    wcscpy(list, L"a,b,a");
    assert_int_equal(RemoveSearchListTokens(list, L"a"), 1);
    assert_int_equal(wcscmp(list, L"a,b"), 0);

    /* multiple removes, mixed positions */
    wcscpy(list, L"a,b,c,d");
    assert_int_equal(RemoveSearchListTokens(list, L"b,d"), 2);
    assert_int_equal(wcscmp(list, L"a,c"), 0);

    /* no matches: list unchanged */
    wcscpy(list, L"a,b,c");
    assert_int_equal(RemoveSearchListTokens(list, L"x,y"), 0);
    assert_int_equal(wcscmp(list, L"a,b,c"), 0);

    /* head removal */
    wcscpy(list, L"a,b,c");
    assert_int_equal(RemoveSearchListTokens(list, L"a"), 1);
    assert_int_equal(wcscmp(list, L"b,c"), 0);

    /* tail removal */
    wcscpy(list, L"a,b,c");
    assert_int_equal(RemoveSearchListTokens(list, L"c"), 1);
    assert_int_equal(wcscmp(list, L"a,b"), 0);

    /* remove every token */
    wcscpy(list, L"a,b");
    assert_int_equal(RemoveSearchListTokens(list, L"a,b"), 2);
    assert_int_equal(wcscmp(list, L""), 0);

    /* duplicate undo tokens drain multiple occurrences */
    wcscpy(list, L"x,x,x");
    assert_int_equal(RemoveSearchListTokens(list, L"x,x"), 2);
    assert_int_equal(wcscmp(list, L"x"), 0);

    /* asking to remove more than is present only removes what's there */
    wcscpy(list, L"x");
    assert_int_equal(RemoveSearchListTokens(list, L"x,x,x"), 1);
    assert_int_equal(wcscmp(list, L""), 0);

    /* empty list */
    wcscpy(list, L"");
    assert_int_equal(RemoveSearchListTokens(list, L"a"), 0);
    assert_int_equal(wcscmp(list, L""), 0);

    /* empty remove */
    wcscpy(list, L"a,b");
    assert_int_equal(RemoveSearchListTokens(list, L""), 0);
    assert_int_equal(wcscmp(list, L"a,b"), 0);

    /* stray empty tokens in the list are tolerated -- the splice only
     * touches the token being removed (and one adjacent comma) */
    wcscpy(list, L"a,,b");
    assert_int_equal(RemoveSearchListTokens(list, L"b"), 1);
    assert_int_equal(wcscmp(list, L"a,"), 0);
}

/* Merge the environments and compare the result with the expected block,
 * including the terminating empty string. A macro, so that failures are
 * reported with the line of the test case. */
#define assert_merge_result(sys_env, usr_env, expected)         \
    do                                                          \
    {                                                           \
        PWSTR env_ = MergeOpenvpnEnvironment(sys_env, usr_env); \
        assert_non_null(env_);                                  \
        size_t size_ = EnvBlockSize(expected);                  \
        assert_int_equal(EnvBlockSize(env_), size_);            \
        assert_memory_equal(env_, expected, size_);             \
        free(env_);                                             \
    } while (0)

static void
test_merge_openvpn_environment(void **state)
{
    /* string literals add the second terminating '\0' of the block */
    PCWSTR sys_env = L"A=sys\0PATH=sys\0TEMP=sys\0USERNAME=sys\0";

    /* user-specific variables come from the user, everything else from the
     * system, and variables only the user defined are dropped */
    assert_merge_result(
        sys_env,
        L"A=usr\0APPDATA=usr\0PATH=usr\0TEMP=usr\0TMP=usr\0USERNAME=usr\0USERPROFILE=usr\0USR_ONLY=usr\0",
        L"A=sys\0PATH=sys\0APPDATA=usr\0TEMP=usr\0TMP=usr\0USERNAME=usr\0USERPROFILE=usr\0");

    /* user-specific variables missing from the user environment are not set */
    assert_merge_result(sys_env, L"TEMP=usr\0", L"A=sys\0PATH=sys\0TEMP=usr\0");

    /* only full names are user-specific variables, not prefixes */
    assert_merge_result(sys_env, L"TEMPDIR=usr\0USER=usr\0", L"A=sys\0PATH=sys\0");

    /* empty environments */
    assert_merge_result(sys_env, L"", L"A=sys\0PATH=sys\0");
    assert_merge_result(L"", L"TEMP=usr\0USR_ONLY=usr\0", L"TEMP=usr\0");
    assert_merge_result(L"", L"", L"");
}

int
wmain(void)
{
    openvpn_unit_test_setup();
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_list_contains_domain),
        cmocka_unit_test(test_convert_itf_dns_domains),
        cmocka_unit_test(test_append_search_list),
        cmocka_unit_test(test_remove_search_list_tokens),
        cmocka_unit_test(test_merge_openvpn_environment),
    };

    int ret = cmocka_run_group_tests_name("openvpnserv tests", tests, NULL, NULL);

    return ret;
}
