/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2023-2024 OpenVPN Inc <sales@openvpn.net>
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
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#undef ENABLE_SYSTEMD

#include "syshead.h"
#include "manage.h"

#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include "test_common.h"

#include "misc.c"

struct management *management; /* global */

/* mocking */
bool
query_user_exec_builtin(void)
{
    /* Loop through configured query_user slots */
    for (int i = 0; i < QUERY_USER_NUMSLOTS && query_user[i].response != NULL; i++)
    {
        check_expected(query_user[i].prompt);
        strncpy(query_user[i].response, mock_ptr_type(char *), query_user[i].response_len);
    }

    return mock();
}
void
management_auth_failure(struct management *man, const char *type, const char *reason)
{
    assert_true(0);
}
bool
management_query_user_pass(struct management *man,
                           struct user_pass *up,
                           const char *type,
                           const unsigned int flags,
                           const char *static_challenge)
{
    assert_true(0);
    return false;
}
/* stubs for some unused functions instead of pulling in too many dependencies */
int
parse_line(const char *line, char **p, const int n, const char *file,
           const int line_num, int msglevel, struct gc_arena *gc)
{
    assert_true(0);
    return 0;
}

/* tooling */
static void
reset_user_pass(struct user_pass *up)
{
    up->defined = false;
    up->token_defined = false;
    up->nocache = false;
    strcpy(up->username, "user");
    strcpy(up->password, "password");
}

static void
test_get_user_pass_defined(void **state)
{
    struct user_pass up = { 0 };
    reset_user_pass(&up);
    up.defined = true;
    assert_true(get_user_pass_cr(&up, NULL, "UT", 0, NULL));
}

static void
test_get_user_pass_needok(void **state)
{
    struct user_pass up = { 0 };
    reset_user_pass(&up);
    unsigned int flags = GET_USER_PASS_NEED_OK;

    expect_string(query_user_exec_builtin, query_user[i].prompt, "NEED-OK|UT|user:");
    will_return(query_user_exec_builtin, "");
    will_return(query_user_exec_builtin, true);
    /*FIXME: query_user_exec() called even though nothing queued */
    will_return(query_user_exec_builtin, true);
    assert_true(get_user_pass_cr(&up, NULL, "UT", flags, NULL));
    assert_true(up.defined);
    assert_string_equal(up.password, "ok");

    reset_user_pass(&up);

    expect_string(query_user_exec_builtin, query_user[i].prompt, "NEED-OK|UT|user:");
    will_return(query_user_exec_builtin, "cancel");
    will_return(query_user_exec_builtin, true);
    /*FIXME: query_user_exec() called even though nothing queued */
    will_return(query_user_exec_builtin, true);
    assert_true(get_user_pass_cr(&up, NULL, "UT", flags, NULL));
    assert_true(up.defined);
    assert_string_equal(up.password, "cancel");
}

static void
test_get_user_pass_inline_creds(void **state)
{
    struct user_pass up = { 0 };
    reset_user_pass(&up);
    unsigned int flags = GET_USER_PASS_INLINE_CREDS;

    /*FIXME: query_user_exec() called even though nothing queued */
    will_return(query_user_exec_builtin, true);
    assert_true(get_user_pass_cr(&up, "iuser\nipassword", "UT", flags, NULL));
    assert_true(up.defined);
    assert_string_equal(up.username, "iuser");
    assert_string_equal(up.password, "ipassword");

    reset_user_pass(&up);

    /* Test various valid characters */
    /*FIXME: query_user_exec() called even though nothing queued */
    will_return(query_user_exec_builtin, true);
    /* FIXME? content after first two lines just ignored */
    assert_true(get_user_pass_cr(&up, "#iuser and 커뮤니티\n//ipasswörd!\nsome other content\nnot relevant", "UT", flags, NULL));
    assert_true(up.defined);
    assert_string_equal(up.username, "#iuser and 커뮤니티");
    assert_string_equal(up.password, "//ipasswörd!");

    reset_user_pass(&up);

    /* Test various invalid characters */
    /*FIXME: query_user_exec() called even though nothing queued */
    will_return(query_user_exec_builtin, true);
    /*FIXME? allows arbitrary crap if c > 127 */
    /*FIXME? silently removes control characters */
    assert_true(get_user_pass_cr(&up, "\tiuser\r\nipass\xffwo\x1erd", "UT", flags, NULL));
    assert_true(up.defined);
    assert_string_equal(up.username, "iuser");
    assert_string_equal(up.password, "ipass\xffword");

    reset_user_pass(&up);

    expect_string(query_user_exec_builtin, query_user[i].prompt, "Enter UT Password:");
    will_return(query_user_exec_builtin, "cpassword");
    will_return(query_user_exec_builtin, true);
    /* will try to retrieve missing password from stdin */
    assert_true(get_user_pass_cr(&up, "iuser", "UT", flags, NULL));
    assert_true(up.defined);
    assert_string_equal(up.username, "iuser");
    assert_string_equal(up.password, "cpassword");

    reset_user_pass(&up);

    flags |= GET_USER_PASS_PASSWORD_ONLY;
    /*FIXME: query_user_exec() called even though nothing queued */
    will_return(query_user_exec_builtin, true);
    assert_true(get_user_pass_cr(&up, "ipassword\n", "UT", flags, NULL));
    assert_true(up.defined);
    assert_string_equal(up.username, "user");
    assert_string_equal(up.password, "ipassword");

    reset_user_pass(&up);

    flags |= GET_USER_PASS_PASSWORD_ONLY;
    expect_string(query_user_exec_builtin, query_user[i].prompt, "Enter UT Password:");
    will_return(query_user_exec_builtin, "cpassword");
    will_return(query_user_exec_builtin, true);
    /* will try to retrieve missing password from stdin */
    assert_true(get_user_pass_cr(&up, "", "UT", flags, NULL));
    assert_true(up.defined);
    assert_string_equal(up.username, "user");
    assert_string_equal(up.password, "cpassword");
}

static void
test_get_user_pass_authfile_stdin(void **state)
{
    struct user_pass up = { 0 };
    reset_user_pass(&up);
    unsigned int flags = 0;

    expect_string(query_user_exec_builtin, query_user[i].prompt, "Enter UT Username:");
    expect_string(query_user_exec_builtin, query_user[i].prompt, "Enter UT Password:");
    will_return(query_user_exec_builtin, "cuser");
    will_return(query_user_exec_builtin, "cpassword");
    will_return(query_user_exec_builtin, true);
    assert_true(get_user_pass_cr(&up, "stdin", "UT", flags, NULL));
    assert_true(up.defined);
    assert_string_equal(up.username, "cuser");
    assert_string_equal(up.password, "cpassword");

    reset_user_pass(&up);

    flags |= GET_USER_PASS_PASSWORD_ONLY;
    expect_string(query_user_exec_builtin, query_user[i].prompt, "Enter UT Password:");
    will_return(query_user_exec_builtin, "cpassword");
    will_return(query_user_exec_builtin, true);
    assert_true(get_user_pass_cr(&up, "stdin", "UT", flags, NULL));
    assert_true(up.defined);
    assert_string_equal(up.username, "user");
    assert_string_equal(up.password, "cpassword");
}

static void
test_get_user_pass_authfile_file(void **state)
{
    struct user_pass up = { 0 };
    reset_user_pass(&up);
    unsigned int flags = 0;

    char authfile[PATH_MAX] = { 0 };
    openvpn_test_get_srcdir_dir(authfile, PATH_MAX, "input/user_pass.txt" );

    /*FIXME: query_user_exec() called even though nothing queued */
    will_return(query_user_exec_builtin, true);
    assert_true(get_user_pass_cr(&up, authfile, "UT", flags, NULL));
    assert_true(up.defined);
    assert_string_equal(up.username, "fuser");
    assert_string_equal(up.password, "fpassword");

    reset_user_pass(&up);

    openvpn_test_get_srcdir_dir(authfile, PATH_MAX, "input/user_only.txt");
    expect_string(query_user_exec_builtin, query_user[i].prompt, "Enter UT Password:");
    will_return(query_user_exec_builtin, "cpassword");
    will_return(query_user_exec_builtin, true);
    /* will try to retrieve missing password from stdin */
    assert_true(get_user_pass_cr(&up, authfile, "UT", flags, NULL));
    assert_true(up.defined);
    assert_string_equal(up.username, "fuser");
    assert_string_equal(up.password, "cpassword");

    reset_user_pass(&up);

    flags |= GET_USER_PASS_PASSWORD_ONLY;
    openvpn_test_get_srcdir_dir(authfile, PATH_MAX, "input/user_only.txt");
    /*FIXME: query_user_exec() called even though nothing queued */
    will_return(query_user_exec_builtin, true);
    assert_true(get_user_pass_cr(&up, authfile, "UT", flags, NULL));
    assert_true(up.defined);
    assert_string_equal(up.username, "user");
    assert_string_equal(up.password, "fuser");
}

#ifdef ENABLE_MANAGEMENT
static void
test_get_user_pass_dynamic_challenge(void **state)
{
    struct user_pass up = { 0 };
    reset_user_pass(&up);
    const char *challenge = "CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l:Y3Ix:Please enter token PIN";
    unsigned int flags = GET_USER_PASS_DYNAMIC_CHALLENGE;

    expect_string(query_user_exec_builtin, query_user[i].prompt, "CHALLENGE: Please enter token PIN");
    will_return(query_user_exec_builtin, "challenge_response");
    will_return(query_user_exec_builtin, true);
    assert_true(get_user_pass_cr(&up, NULL, "UT", flags, challenge));
    assert_true(up.defined);
    assert_string_equal(up.username, "cr1");
    assert_string_equal(up.password, "CRV1::Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l::challenge_response");
}

static void
test_get_user_pass_static_challenge(void **state)
{
    struct user_pass up = { 0 };
    reset_user_pass(&up);
    const char *challenge = "Please enter token PIN";
    unsigned int flags = GET_USER_PASS_STATIC_CHALLENGE;

    expect_string(query_user_exec_builtin, query_user[i].prompt, "Enter UT Username:");
    will_return(query_user_exec_builtin, "cuser");
    expect_string(query_user_exec_builtin, query_user[i].prompt, "Enter UT Password:");
    will_return(query_user_exec_builtin, "cpassword");
    will_return(query_user_exec_builtin, true);
    expect_string(query_user_exec_builtin, query_user[i].prompt, "CHALLENGE: Please enter token PIN");
    will_return(query_user_exec_builtin, "challenge_response");
    will_return(query_user_exec_builtin, true);
    assert_true(get_user_pass_cr(&up, NULL, "UT", flags, challenge));
    assert_true(up.defined);
    assert_string_equal(up.username, "cuser");
    /* SCRV1:cpassword:challenge_response but base64-encoded */
    assert_string_equal(up.password, "SCRV1:Y3Bhc3N3b3Jk:Y2hhbGxlbmdlX3Jlc3BvbnNl");

    reset_user_pass(&up);

    flags |= GET_USER_PASS_INLINE_CREDS;

    /*FIXME: query_user_exec() called even though nothing queued */
    will_return(query_user_exec_builtin, true);
    expect_string(query_user_exec_builtin, query_user[i].prompt, "CHALLENGE: Please enter token PIN");
    will_return(query_user_exec_builtin, "challenge_response");
    will_return(query_user_exec_builtin, true);
    assert_true(get_user_pass_cr(&up, "iuser\nipassword", "UT", flags, challenge));
    assert_true(up.defined);
    assert_string_equal(up.username, "iuser");
    /* SCRV1:ipassword:challenge_response but base64-encoded */
    assert_string_equal(up.password, "SCRV1:aXBhc3N3b3Jk:Y2hhbGxlbmdlX3Jlc3BvbnNl");
}
#endif /* ENABLE_MANAGEMENT */

const struct CMUnitTest user_pass_tests[] = {
    cmocka_unit_test(test_get_user_pass_defined),
    cmocka_unit_test(test_get_user_pass_needok),
    cmocka_unit_test(test_get_user_pass_inline_creds),
    cmocka_unit_test(test_get_user_pass_authfile_stdin),
    cmocka_unit_test(test_get_user_pass_authfile_file),
#ifdef ENABLE_MANAGEMENT
    cmocka_unit_test(test_get_user_pass_dynamic_challenge),
    cmocka_unit_test(test_get_user_pass_static_challenge),
#endif /* ENABLE_MANAGEMENT */
};

int
main(void)
{
    openvpn_unit_test_setup();
    return cmocka_run_group_tests(user_pass_tests, NULL, NULL);
}
