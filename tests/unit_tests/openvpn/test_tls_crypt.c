/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2017 Fox Crypto B.V. <openvpn@fox-it.com>
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

#ifdef ENABLE_CRYPTO

#include "syshead.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "tls_crypt.h"

#include "mock_msg.h"

#define TESTBUF_SIZE            128

const char plaintext_short[1];

struct test_context {
    struct crypto_options co;
    struct key_type kt;
    struct buffer source;
    struct buffer ciphertext;
    struct buffer unwrapped;
};

static int
setup(void **state) {
    struct test_context *ctx = calloc(1, sizeof(*ctx));
    *state = ctx;

    ctx->kt.cipher = cipher_kt_get("AES-256-CTR");
    ctx->kt.digest = md_kt_get("SHA256");
    if (!ctx->kt.cipher)
    {
        printf("No AES-256-CTR support, skipping test.\n");
        return 0;
    }
    if (!ctx->kt.digest)
    {
        printf("No HMAC-SHA256 support, skipping test.\n");
        return 0;
    }
    ctx->kt.cipher_length = cipher_kt_key_size(ctx->kt.cipher);
    ctx->kt.hmac_length = md_kt_size(ctx->kt.digest);

    struct key key = { 0 };

    init_key_ctx(&ctx->co.key_ctx_bi.encrypt, &key, &ctx->kt, true, "TEST");
    init_key_ctx(&ctx->co.key_ctx_bi.decrypt, &key, &ctx->kt, false, "TEST");

    packet_id_init(&ctx->co.packet_id, 0, 0, "test", 0);

    ctx->source = alloc_buf(TESTBUF_SIZE);
    ctx->ciphertext = alloc_buf(TESTBUF_SIZE);
    ctx->unwrapped = alloc_buf(TESTBUF_SIZE);

    /* Write test plaintext */
    buf_write(&ctx->source, plaintext_short, sizeof(plaintext_short));

    /* Write dummy opcode and session id */
    buf_write(&ctx->ciphertext, "012345678", 1 + 8);

    return 0;
}

static int
teardown(void **state) {
    struct test_context *ctx = (struct test_context *) *state;

    free_buf(&ctx->source);
    free_buf(&ctx->ciphertext);
    free_buf(&ctx->unwrapped);

    free_key_ctx_bi(&ctx->co.key_ctx_bi);

    free(ctx);

    return 0;
}

static void skip_if_tls_crypt_not_supported(struct test_context *ctx)
{
    if (!ctx->kt.cipher || !ctx->kt.digest)
    {
        skip();
    }
}

/**
 * Check that short messages are successfully wrapped-and-unwrapped.
 */
static void
tls_crypt_loopback(void **state) {
    struct test_context *ctx = (struct test_context *) *state;

    skip_if_tls_crypt_not_supported(ctx);

    assert_true(tls_crypt_wrap(&ctx->source, &ctx->ciphertext, &ctx->co));
    assert_true(BLEN(&ctx->source) < BLEN(&ctx->ciphertext));
    assert_true(tls_crypt_unwrap(&ctx->ciphertext, &ctx->unwrapped, &ctx->co));
    assert_int_equal(BLEN(&ctx->source), BLEN(&ctx->unwrapped));
    assert_memory_equal(BPTR(&ctx->source), BPTR(&ctx->unwrapped),
                        BLEN(&ctx->source));
}

/**
 * Check that zero-byte messages are successfully wrapped-and-unwrapped.
 */
static void
tls_crypt_loopback_zero_len(void **state) {
    struct test_context *ctx = (struct test_context *) *state;

    skip_if_tls_crypt_not_supported(ctx);

    buf_clear(&ctx->source);

    assert_true(tls_crypt_wrap(&ctx->source, &ctx->ciphertext, &ctx->co));
    assert_true(BLEN(&ctx->source) < BLEN(&ctx->ciphertext));
    assert_true(tls_crypt_unwrap(&ctx->ciphertext, &ctx->unwrapped, &ctx->co));
    assert_int_equal(BLEN(&ctx->source), BLEN(&ctx->unwrapped));
    assert_memory_equal(BPTR(&ctx->source), BPTR(&ctx->unwrapped),
                        BLEN(&ctx->source));
}

/**
 * Check that max-length messages are successfully wrapped-and-unwrapped.
 */
static void
tls_crypt_loopback_max_len(void **state) {
    struct test_context *ctx = (struct test_context *) *state;

    skip_if_tls_crypt_not_supported(ctx);

    buf_clear(&ctx->source);
    assert_non_null(buf_write_alloc(&ctx->source,
                                    TESTBUF_SIZE - BLEN(&ctx->ciphertext) - tls_crypt_buf_overhead()));

    assert_true(tls_crypt_wrap(&ctx->source, &ctx->ciphertext, &ctx->co));
    assert_true(BLEN(&ctx->source) < BLEN(&ctx->ciphertext));
    assert_true(tls_crypt_unwrap(&ctx->ciphertext, &ctx->unwrapped, &ctx->co));
    assert_int_equal(BLEN(&ctx->source), BLEN(&ctx->unwrapped));
    assert_memory_equal(BPTR(&ctx->source), BPTR(&ctx->unwrapped),
                        BLEN(&ctx->source));
}

/**
 * Check that too-long messages are gracefully rejected.
 */
static void
tls_crypt_fail_msg_too_long(void **state) {
    struct test_context *ctx = (struct test_context *) *state;

    skip_if_tls_crypt_not_supported(ctx);

    buf_clear(&ctx->source);
    assert_non_null(buf_write_alloc(&ctx->source,
                                    TESTBUF_SIZE - BLEN(&ctx->ciphertext) - tls_crypt_buf_overhead() + 1));
    assert_false(tls_crypt_wrap(&ctx->source, &ctx->ciphertext, &ctx->co));
}

/**
 * Check that packets that were wrapped (or unwrapped) with a different key
 * are not accepted.
 */
static void
tls_crypt_fail_invalid_key(void **state) {
    struct test_context *ctx = (struct test_context *) *state;

    skip_if_tls_crypt_not_supported(ctx);

    /* Change decrypt key */
    struct key key = { { 1 } };
    free_key_ctx(&ctx->co.key_ctx_bi.decrypt);
    init_key_ctx(&ctx->co.key_ctx_bi.decrypt, &key, &ctx->kt, false, "TEST");

    assert_true(tls_crypt_wrap(&ctx->source, &ctx->ciphertext, &ctx->co));
    assert_true(BLEN(&ctx->source) < BLEN(&ctx->ciphertext));
    assert_false(tls_crypt_unwrap(&ctx->ciphertext, &ctx->unwrapped, &ctx->co));
}

/**
 * Check that replayed packets are not accepted.
 */
static void
tls_crypt_fail_replay(void **state) {
    struct test_context *ctx = (struct test_context *) *state;

    skip_if_tls_crypt_not_supported(ctx);

    assert_true(tls_crypt_wrap(&ctx->source, &ctx->ciphertext, &ctx->co));
    assert_true(BLEN(&ctx->source) < BLEN(&ctx->ciphertext));
    struct buffer tmp = ctx->ciphertext;
    assert_true(tls_crypt_unwrap(&tmp, &ctx->unwrapped, &ctx->co));
    buf_clear(&ctx->unwrapped);
    assert_false(tls_crypt_unwrap(&ctx->ciphertext, &ctx->unwrapped, &ctx->co));
}

/**
 * Check that packet replays are accepted when CO_IGNORE_PACKET_ID is set. This
 * is used for the first control channel packet that arrives, because we don't
 * know the packet ID yet.
 */
static void
tls_crypt_ignore_replay(void **state) {
    struct test_context *ctx = (struct test_context *) *state;

    skip_if_tls_crypt_not_supported(ctx);

    ctx->co.flags |= CO_IGNORE_PACKET_ID;

    assert_true(tls_crypt_wrap(&ctx->source, &ctx->ciphertext, &ctx->co));
    assert_true(BLEN(&ctx->source) < BLEN(&ctx->ciphertext));
    struct buffer tmp = ctx->ciphertext;
    assert_true(tls_crypt_unwrap(&tmp, &ctx->unwrapped, &ctx->co));
    buf_clear(&ctx->unwrapped);
    assert_true(tls_crypt_unwrap(&ctx->ciphertext, &ctx->unwrapped, &ctx->co));
}

int
main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(tls_crypt_loopback, setup, teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_loopback_zero_len,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_loopback_max_len,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_fail_msg_too_long,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_fail_invalid_key,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_fail_replay,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_ignore_replay,
                                        setup, teardown),
    };

#if defined(ENABLE_CRYPTO_OPENSSL)
    OpenSSL_add_all_algorithms();
#endif

    int ret = cmocka_run_group_tests_name("tls-crypt tests", tests, NULL, NULL);

#if defined(ENABLE_CRYPTO_OPENSSL)
    EVP_cleanup();
#endif

    return ret;
}

#endif /* ENABLE_CRYPTO */
