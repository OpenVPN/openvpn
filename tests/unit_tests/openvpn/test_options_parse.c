/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2025 OpenVPN Inc <sales@openvpn.net>
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

#include "options.h"
#include "test_common.h"
#include "mock_msg.h"

void
__wrap_add_option(struct options *options, char *p[], bool is_inline, const char *file,
                  int line, const int level, const msglvl_t msglevel,
                  const unsigned int permission_mask, unsigned int *option_types_found,
                  struct env_set *es)
{
    function_called();
    check_expected(p);
    check_expected(is_inline);
}

void
__wrap_remove_option(struct context *c, struct options *options, char *p[], bool is_inline,
                     const char *file, int line, const msglvl_t msglevel,
                     const unsigned int permission_mask, unsigned int *option_types_found,
                     struct env_set *es)
{
}

void
__wrap_update_option(struct context *c, struct options *options, char *p[], bool is_inline,
                     const char *file, int line, const int level, const msglvl_t msglevel,
                     const unsigned int permission_mask, unsigned int *option_types_found,
                     struct env_set *es, unsigned int *update_options_found)
{
}

void
__wrap_usage(void)
{
}

/* for building long texts */
#define A_TIMES_256 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAO"

static void
test_parse_line(void **state)
{
    char *p[MAX_PARMS + 1] = { 0 };
    struct gc_arena gc = gc_new();
    int res = 0;

#define PARSE_LINE_TST(string)                                                          \
    do                                                                                  \
    {                                                                                   \
        CLEAR(p);                                                                       \
        res = parse_line(string, p, SIZE(p) - 1, "test_options_parse", 1, M_INFO, &gc); \
    } while (0);

    /* basic example */
    PARSE_LINE_TST("some-opt firstparm second-parm");
    assert_int_equal(res, 3);
    assert_string_equal(p[0], "some-opt");
    assert_string_equal(p[1], "firstparm");
    assert_string_equal(p[2], "second-parm");
    assert_null(p[res]);

    /* basic quoting, -- is not handled special */
    PARSE_LINE_TST("--some-opt 'first parm' \"second' 'parm\"");
    assert_int_equal(res, 3);
    assert_string_equal(p[0], "--some-opt");
    assert_string_equal(p[1], "first parm");
    assert_string_equal(p[2], "second' 'parm");
    assert_null(p[res]);

    /* escaped quotes */
    PARSE_LINE_TST("\"some opt\" 'first\" \"parm' \"second\\\" \\\"parm\"");
    assert_int_equal(res, 3);
    assert_string_equal(p[0], "some opt");
    assert_string_equal(p[1], "first\" \"parm");
    assert_string_equal(p[2], "second\" \"parm");
    assert_null(p[res]);

    /* missing closing quote */
    PARSE_LINE_TST("--some-opt 'first parm \"second parm\"");
    assert_int_equal(res, 0);

    /* escaped backslash */
    PARSE_LINE_TST("some\\\\opt C:\\\\directory\\\\file");
    assert_int_equal(res, 2);
    assert_string_equal(p[0], "some\\opt");
    assert_string_equal(p[1], "C:\\directory\\file");
    assert_null(p[res]);

    /* comment chars are not special inside parameter */
    PARSE_LINE_TST("some-opt firstparm; second#parm");
    assert_int_equal(res, 3);
    assert_string_equal(p[0], "some-opt");
    assert_string_equal(p[1], "firstparm;");
    assert_string_equal(p[2], "second#parm");
    assert_null(p[res]);

    /* comment */
    PARSE_LINE_TST("some-opt firstparm # secondparm");
    assert_int_equal(res, 2);
    assert_string_equal(p[0], "some-opt");
    assert_string_equal(p[1], "firstparm");
    assert_null(p[res]);

    /* parameter just long enough */
    PARSE_LINE_TST("opt " A_TIMES_256);
    assert_int_equal(res, 2);
    assert_string_equal(p[0], "opt");
    assert_string_equal(p[1], A_TIMES_256);
    assert_null(p[res]);

    /* quoting doesn't count for parameter length */
    PARSE_LINE_TST("opt \"" A_TIMES_256 "\"");
    assert_int_equal(res, 2);
    assert_string_equal(p[0], "opt");
    assert_string_equal(p[1], A_TIMES_256);
    assert_null(p[res]);

    /* very long line */
    PARSE_LINE_TST("opt " A_TIMES_256 " " A_TIMES_256 " " A_TIMES_256 " " A_TIMES_256);
    assert_int_equal(res, 5);
    assert_string_equal(p[0], "opt");
    assert_string_equal(p[1], A_TIMES_256);
    assert_string_equal(p[2], A_TIMES_256);
    assert_string_equal(p[3], A_TIMES_256);
    assert_string_equal(p[4], A_TIMES_256);
    assert_null(p[res]);

    /* parameter too long */
    PARSE_LINE_TST("opt " A_TIMES_256 "B");
    assert_int_equal(res, 0);

    /* max parameters */
    PARSE_LINE_TST("0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15");
    assert_int_equal(res, MAX_PARMS);
    char num[3];
    for (int i = 0; i < MAX_PARMS; i++)
    {
        assert_true(snprintf(num, 3, "%d", i) < 3);
        assert_string_equal(p[i], num);
    }
    assert_null(p[res]);

    /* too many parameters, overflow is ignored */
    PARSE_LINE_TST("0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16");
    assert_int_equal(res, MAX_PARMS);
    for (int i = 0; i < MAX_PARMS; i++)
    {
        assert_true(snprintf(num, 3, "%d", i) < 3);
        assert_string_equal(p[i], num);
    }
    assert_null(p[res]);

    gc_free(&gc);
}

static void
read_single_config(struct options *options, const char *config)
{
    unsigned int option_types_found = 0;
    struct env_set es;
    CLEAR(es);
    read_config_string("test_options_parse", options, config, M_INFO, OPT_P_DEFAULT,
                       &option_types_found, &es);
}

/* compat with various versions of cmocka.h
 * Older versions have LargestIntegralType. Newer
 * versions use uintmax_t. But LargestIntegralType
 * is not guaranteed to be equal to uintmax_t, so
 * we can't use that unconditionally. So we only use
 * it if cmocka.h does not define LargestIntegralType.
 */
#ifndef LargestIntegralType
#define LargestIntegralType uintmax_t
#endif

union tokens_parameter
{
    LargestIntegralType as_int;
    void *as_pointer;
};

static int
check_tokens(const LargestIntegralType value, const LargestIntegralType expected)
{
    union tokens_parameter temp;
    temp.as_int = value;
    const char **p = (const char **)temp.as_pointer;
    temp.as_int = expected;
    const char **expected_p = (const char **)temp.as_pointer;
    for (int i = 0; i < MAX_PARMS; i++)
    {
        if (!p[i] && !expected_p[i])
        {
            return true;
        }
        if ((p[i] && !expected_p[i])
            || (!p[i] && expected_p[i]))
        {
            fprintf(stderr, "diff at i=%d\n", i);
            return false;
        }
        if (strcmp(p[i], expected_p[i]))
        {
            fprintf(stderr, "diff at i=%d, p=<%s> ep=<%s>\n", i, p[i], expected_p[i]);
            return false;
        }
    }
    fprintf(stderr, "fallthrough");
    return false;
}

static void
test_read_config(void **state)
{
    struct options o;
    CLEAR(o); /* NB: avoiding init_options to limit dependencies */
    gc_init(&o.gc);
    gc_init(&o.dns_options.gc);
    o.gc_owned = true;

    char *p_expect_someopt[MAX_PARMS];
    char *p_expect_otheropt[MAX_PARMS];
    char *p_expect_inlineopt[MAX_PARMS];
    CLEAR(p_expect_someopt);
    CLEAR(p_expect_otheropt);
    CLEAR(p_expect_inlineopt);
    p_expect_someopt[0] = "someopt";
    p_expect_someopt[1] = "parm1";
    p_expect_someopt[2] = "parm2";
    p_expect_otheropt[0] = "otheropt";
    p_expect_otheropt[1] = "1";
    p_expect_otheropt[2] = "2";
    p_expect_inlineopt[0] = "inlineopt";
    p_expect_inlineopt[1] = "some text\nother text\n";

    /* basic test */
    expect_function_call(__wrap_add_option);
    expect_check(__wrap_add_option, p, check_tokens, p_expect_someopt);
    expect_value(__wrap_add_option, is_inline, 0);
    expect_function_call(__wrap_add_option);
    expect_check(__wrap_add_option, p, check_tokens, p_expect_otheropt);
    expect_value(__wrap_add_option, is_inline, 0);
    read_single_config(&o, "someopt parm1 parm2\n  otheropt 1 2");

    /* -- gets stripped */
    expect_function_call(__wrap_add_option);
    expect_check(__wrap_add_option, p, check_tokens, p_expect_someopt);
    expect_value(__wrap_add_option, is_inline, 0);
    expect_function_call(__wrap_add_option);
    expect_check(__wrap_add_option, p, check_tokens, p_expect_otheropt);
    expect_value(__wrap_add_option, is_inline, 0);
    read_single_config(&o, "someopt parm1 parm2\n\t--otheropt 1 2");

    /* inline options */
    expect_function_call(__wrap_add_option);
    expect_check(__wrap_add_option, p, check_tokens, p_expect_inlineopt);
    expect_value(__wrap_add_option, is_inline, 1);
    read_single_config(&o, "<inlineopt>\nsome text\nother text\n</inlineopt>");

    p_expect_inlineopt[0] = "inlineopt";
    p_expect_inlineopt[1] = A_TIMES_256 A_TIMES_256 A_TIMES_256 A_TIMES_256 A_TIMES_256 "\n";
    expect_function_call(__wrap_add_option);
    expect_check(__wrap_add_option, p, check_tokens, p_expect_inlineopt);
    expect_value(__wrap_add_option, is_inline, 1);
    read_single_config(&o, "<inlineopt>\n" A_TIMES_256 A_TIMES_256 A_TIMES_256 A_TIMES_256 A_TIMES_256 "\n</inlineopt>");

    gc_free(&o.gc);
    gc_free(&o.dns_options.gc);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_line),
        cmocka_unit_test(test_read_config),
    };

    return cmocka_run_group_tests_name("options_parse", tests, NULL, NULL);
}
