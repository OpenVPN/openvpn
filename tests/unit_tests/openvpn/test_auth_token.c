/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
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
#endif

#include "syshead.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "auth_token.c"

struct test_context {
    struct tls_multi multi;
    struct key_type kt;
    struct user_pass up;
    struct tls_session *session;
};

/* Dummy functions that do nothing to mock the functionality */
void
send_push_reply_auth_token(struct tls_multi *multi)
{
}

void
auth_set_client_reason(struct tls_multi *multi, const char *reason)
{

}

static const char *now0key0 = "SESS_ID_AT_0123456789abcdefAAAAAAAAAAAAAAAAAAAAAE5JsQJOVfo8jnI3RL3tBaR5NkE4yPfcylFUHmHSc5Bu";

static const char *zeroinline = "-----BEGIN OpenVPN auth-token server key-----\n"
                                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
                                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
                                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
                                "-----END OpenVPN auth-token server key-----";

static const char *allx01inline = "-----BEGIN OpenVPN auth-token server key-----\n"
                                  "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n"
                                  "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n"
                                  "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n"
                                  "-----END OpenVPN auth-token server key-----";

static const char *random_key = "-----BEGIN OpenVPN auth-token server key-----\n"
                                "+mmmf7IQ5cymtMVjKYTWk8IOcYanRlpQmV9Tb3EjkHYxueBVDg3yqRgzeBlVGzNLD//rAPiOVhau\n"
                                "3NDBjNOQB8951bfs7Cc2mYfay92Bh2gRJ5XEM/DMfzCWN+7uU6NWoTTHr4FuojnIQtjtqVAj/JS9\n"
                                "w+dTSp/vYHl+c7uHd19uVRu/qLqV85+rm4tUGIjO7FfYuwyPqwmhuIsi3hs9QkSimh888FmBpoKY\n"
                                "/tbKVTJZmSERKti9KEwtV2eVAR0znN5KW7lCB3mHVAhN7bUpcoDjfCzYIFARxwswTFu9gFkwqUMY\n"
                                "I1KUOgIsVNs4llACioeXplYekWETR+YkJwDc/A==\n"
                                "-----END OpenVPN auth-token server key-----";

static const char *random_token = "SESS_ID_AT_ThhRItzOKNKrh3dfAAAAAFwzHpwAAAAAXDMenDdrq0RoH3dkA1f7O3wO+7kZcx2DusVZrRmFlWQM9HOb";


static int
setup(void **state)
{
    struct test_context *ctx = calloc(1, sizeof(*ctx));
    *state = ctx;

    struct key key = { 0 };

    ctx->kt = auth_token_kt();
    if (!ctx->kt.digest)
    {
        return 0;
    }
    ctx->multi.opt.auth_token_generate = true;
    ctx->multi.opt.auth_token_lifetime = 3000;
    ctx->session = &ctx->multi.session[TM_ACTIVE];

    ctx->session->opt = calloc(1, sizeof(struct tls_options));
    ctx->session->opt->renegotiate_seconds = 240;
    ctx->session->opt->auth_token_renewal = 120;
    ctx->session->opt->auth_token_lifetime = 3000;

    strcpy(ctx->up.username, "test user name");
    strcpy(ctx->up.password, "ignored");

    init_key_ctx(&ctx->multi.opt.auth_token_key, &key, &ctx->kt, false, "TEST");

    now = 0;
    return 0;
}

static int
teardown(void **state)
{
    struct test_context *ctx = (struct test_context *) *state;

    free_key_ctx(&ctx->multi.opt.auth_token_key);
    wipe_auth_token(&ctx->multi);

    free(ctx->session->opt);
    free(ctx);

    return 0;
}

static void
auth_token_basic_test(void **state)
{
    struct test_context *ctx = (struct test_context *) *state;

    generate_auth_token(&ctx->up, &ctx->multi);
    strcpy(ctx->up.password, ctx->multi.auth_token);
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK);
}

static void
auth_token_fail_invalid_key(void **state)
{
    struct test_context *ctx = (struct test_context *) *state;

    generate_auth_token(&ctx->up, &ctx->multi);
    strcpy(ctx->up.password, ctx->multi.auth_token);
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK);

    /* Change auth-token key */
    struct key key;
    memset(&key, '1', sizeof(key));
    free_key_ctx(&ctx->multi.opt.auth_token_key);
    init_key_ctx(&ctx->multi.opt.auth_token_key, &key, &ctx->kt, false, "TEST");

    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session), 0);

    /* Load original test key again */
    memset(&key, 0, sizeof(key));
    free_key_ctx(&ctx->multi.opt.auth_token_key);
    init_key_ctx(&ctx->multi.opt.auth_token_key, &key, &ctx->kt, false, "TEST");
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK);

}

static void
auth_token_test_timeout(void **state)
{
    struct test_context *ctx = (struct test_context *) *state;

    now = 100000;
    generate_auth_token(&ctx->up, &ctx->multi);

    strcpy(ctx->up.password, ctx->multi.auth_token);
    free(ctx->multi.auth_token_initial);
    ctx->multi.auth_token_initial = NULL;

    /* No time has passed */
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK);

    /* Token before validity, should be rejected */
    now = 100000 - 100;
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK|AUTH_TOKEN_EXPIRED);

    /* Token no valid for renegotiate_seconds but still for renewal_time */
    now = 100000 + 2*ctx->session->opt->renegotiate_seconds - 20;
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK|AUTH_TOKEN_EXPIRED);


    now = 100000 + 2*ctx->session->opt->auth_token_renewal - 20;
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK);

    /* Token past validity, should be rejected */
    now = 100000 + 2*ctx->session->opt->renegotiate_seconds + 20;
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK|AUTH_TOKEN_EXPIRED);

    /* But not when we reached our timeout */
    now = 100000 + ctx->session->opt->auth_token_lifetime + 1;
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK|AUTH_TOKEN_EXPIRED);

    free(ctx->multi.auth_token_initial);
    ctx->multi.auth_token_initial = NULL;

    /* regenerate the token util it hits the expiry */
    now = 100000;
    while (now < 100000 + ctx->session->opt->auth_token_lifetime + 1)
    {
        assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                         AUTH_TOKEN_HMAC_OK);
        generate_auth_token(&ctx->up, &ctx->multi);
        strcpy(ctx->up.password, ctx->multi.auth_token);
        now += ctx->session->opt->auth_token_renewal;
    }


    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK|AUTH_TOKEN_EXPIRED);
    ctx->multi.opt.auth_token_lifetime = 0;

    /* Non expiring token should be fine */
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK);
}

static void
zerohmac(char *token)
{
    char *hmacstart = token + AUTH_TOKEN_SESSION_ID_LEN
                      + strlen(SESSION_ID_PREFIX) + 2*sizeof(uint64_t);
    memset(hmacstart, 0x8d, strlen(hmacstart));
}

static void
auth_token_test_known_keys(void **state)
{
    struct test_context *ctx = (struct test_context *) *state;

    now = 0;
    /* Preload the session id so the same session id is used here */
    ctx->multi.auth_token_initial = strdup(now0key0);

    /* Zero the hmac part to ensure we have a newly generated token */
    zerohmac(ctx->multi.auth_token_initial);

    generate_auth_token(&ctx->up, &ctx->multi);

    assert_string_equal(now0key0, ctx->multi.auth_token);

    strcpy(ctx->up.password, ctx->multi.auth_token);
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK);
}

static const char *lastsesion_statevalue;
void
setenv_str(struct env_set *es, const char *name, const char *value)
{
    if (streq(name, "session_state"))
    {
        lastsesion_statevalue = value;
    }
}

void
auth_token_test_session_mismatch(void **state)
{
    struct test_context *ctx = (struct test_context *) *state;

    /* Generate first auth token and check it is correct */
    generate_auth_token(&ctx->up, &ctx->multi);
    strcpy(ctx->up.password, ctx->multi.auth_token);
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK);

    char *token_sessiona = strdup(ctx->multi.auth_token);

    /* Generate second token */
    wipe_auth_token(&ctx->multi);

    generate_auth_token(&ctx->up, &ctx->multi);
    strcpy(ctx->up.password, ctx->multi.auth_token);
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK);

    assert_int_not_equal(0, memcmp(ctx->multi.auth_token_initial + strlen(SESSION_ID_PREFIX),
                                   token_sessiona + strlen(SESSION_ID_PREFIX),
                                   AUTH_TOKEN_SESSION_ID_BASE64_LEN));

    /* The first token is valid but should trigger the invalid response since
     * the session id is not the same */
    strcpy(ctx->up.password, token_sessiona);
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session), 0);
    free(token_sessiona);
}

static void
auth_token_test_empty_user(void **state)
{
    struct test_context *ctx = (struct test_context *) *state;

    CLEAR(ctx->up.username);
    now = 0;

    generate_auth_token(&ctx->up, &ctx->multi);
    strcpy(ctx->up.password, ctx->multi.auth_token);
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK);

    now = 100000;
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK|AUTH_TOKEN_EXPIRED);
    strcpy(ctx->up.username, "test user name");

    now = 0;
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK|AUTH_TOKEN_VALID_EMPTYUSER);

    strcpy(ctx->up.username, "test user name");
    now = 100000;
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     AUTH_TOKEN_HMAC_OK|AUTH_TOKEN_EXPIRED|AUTH_TOKEN_VALID_EMPTYUSER);

    zerohmac(ctx->up.password);
    assert_int_equal(verify_auth_token(&ctx->up, &ctx->multi, ctx->session),
                     0);
}

static void
auth_token_test_env(void **state)
{
    struct test_context *ctx = (struct test_context *) *state;

    struct key_state *ks = &ctx->multi.session[TM_ACTIVE].key[KS_PRIMARY];

    ks->auth_token_state_flags = 0;
    ctx->multi.auth_token = NULL;
    add_session_token_env(ctx->session, &ctx->multi, &ctx->up);
    assert_string_equal(lastsesion_statevalue, "Initial");

    ks->auth_token_state_flags = 0;
    strcpy(ctx->up.password, now0key0);
    add_session_token_env(ctx->session, &ctx->multi, &ctx->up);
    assert_string_equal(lastsesion_statevalue, "Invalid");

    ks->auth_token_state_flags = AUTH_TOKEN_HMAC_OK;
    add_session_token_env(ctx->session, &ctx->multi, &ctx->up);
    assert_string_equal(lastsesion_statevalue, "Authenticated");

    ks->auth_token_state_flags = AUTH_TOKEN_HMAC_OK|AUTH_TOKEN_EXPIRED;
    add_session_token_env(ctx->session, &ctx->multi, &ctx->up);
    assert_string_equal(lastsesion_statevalue, "Expired");

    ks->auth_token_state_flags = AUTH_TOKEN_HMAC_OK|AUTH_TOKEN_VALID_EMPTYUSER;
    add_session_token_env(ctx->session, &ctx->multi, &ctx->up);
    assert_string_equal(lastsesion_statevalue, "AuthenticatedEmptyUser");

    ks->auth_token_state_flags = AUTH_TOKEN_HMAC_OK|AUTH_TOKEN_EXPIRED|AUTH_TOKEN_VALID_EMPTYUSER;
    add_session_token_env(ctx->session, &ctx->multi, &ctx->up);
    assert_string_equal(lastsesion_statevalue, "ExpiredEmptyUser");
}

static void
auth_token_test_random_keys(void **state)
{
    struct test_context *ctx = (struct test_context *) *state;

    now = 0x5c331e9c;
    /* Preload the session id so the same session id is used here */
    ctx->multi.auth_token_initial = strdup(random_token);

    free_key_ctx(&ctx->multi.opt.auth_token_key);
    auth_token_init_secret(&ctx->multi.opt.auth_token_key, random_key, true);

    /* Zero the hmac part to ensure we have a newly generated token */
    zerohmac(ctx->multi.auth_token_initial);

    generate_auth_token(&ctx->up, &ctx->multi);

    assert_string_equal(random_token, ctx->multi.auth_token);

    strcpy(ctx->up.password, ctx->multi.auth_token);
    assert_true(verify_auth_token(&ctx->up, &ctx->multi, ctx->session));
}


static void
auth_token_test_key_load(void **state)
{
    struct test_context *ctx = (struct test_context *) *state;

    free_key_ctx(&ctx->multi.opt.auth_token_key);
    auth_token_init_secret(&ctx->multi.opt.auth_token_key, zeroinline, true);
    strcpy(ctx->up.password, now0key0);
    assert_true(verify_auth_token(&ctx->up, &ctx->multi, ctx->session));

    free_key_ctx(&ctx->multi.opt.auth_token_key);
    auth_token_init_secret(&ctx->multi.opt.auth_token_key, allx01inline, true);
    assert_false(verify_auth_token(&ctx->up, &ctx->multi, ctx->session));
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(auth_token_basic_test, setup, teardown),
        cmocka_unit_test_setup_teardown(auth_token_fail_invalid_key, setup, teardown),
        cmocka_unit_test_setup_teardown(auth_token_test_known_keys, setup, teardown),
        cmocka_unit_test_setup_teardown(auth_token_test_empty_user, setup, teardown),
        cmocka_unit_test_setup_teardown(auth_token_test_env, setup, teardown),
        cmocka_unit_test_setup_teardown(auth_token_test_random_keys, setup, teardown),
        cmocka_unit_test_setup_teardown(auth_token_test_key_load, setup, teardown),
        cmocka_unit_test_setup_teardown(auth_token_test_timeout, setup, teardown),
        cmocka_unit_test_setup_teardown(auth_token_test_session_mismatch, setup, teardown)
    };

#if defined(ENABLE_CRYPTO_OPENSSL)
    OpenSSL_add_all_algorithms();
#endif

    int ret = cmocka_run_group_tests_name("auth-token tests", tests, NULL, NULL);

    return ret;
}
