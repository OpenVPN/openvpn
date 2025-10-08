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

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_line),
    };

    return cmocka_run_group_tests_name("options_parse", tests, NULL, NULL);
}
