/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2018 Fox Crypto B.V. <openvpn@fox-it.com>
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

#include "syshead.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "tls_crypt.c"

#include "mock_msg.h"

#define TESTBUF_SIZE            128

const char plaintext_short[1];

struct test_tls_crypt_context {
    struct crypto_options co;
    struct key_type kt;
    struct buffer source;
    struct buffer ciphertext;
    struct buffer unwrapped;
};

static int
test_tls_crypt_setup(void **state) {
    struct test_tls_crypt_context *ctx = calloc(1, sizeof(*ctx));
    *state = ctx;

    struct key key = { 0 };

    ctx->kt = tls_crypt_kt();
    if (!ctx->kt.cipher || !ctx->kt.digest)
    {
        return 0;
    }
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
test_tls_crypt_teardown(void **state) {
    struct test_tls_crypt_context *ctx =
            (struct test_tls_crypt_context *)*state;

    free_buf(&ctx->source);
    free_buf(&ctx->ciphertext);
    free_buf(&ctx->unwrapped);

    free_key_ctx_bi(&ctx->co.key_ctx_bi);

    free(ctx);

    return 0;
}

static void skip_if_tls_crypt_not_supported(struct test_tls_crypt_context *ctx)
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
    struct test_tls_crypt_context *ctx = (struct test_tls_crypt_context *) *state;

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
    struct test_tls_crypt_context *ctx = (struct test_tls_crypt_context *) *state;

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
    struct test_tls_crypt_context *ctx = (struct test_tls_crypt_context *) *state;

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
    struct test_tls_crypt_context *ctx = (struct test_tls_crypt_context *) *state;

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
    struct test_tls_crypt_context *ctx = (struct test_tls_crypt_context *) *state;

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
    struct test_tls_crypt_context *ctx = (struct test_tls_crypt_context *) *state;

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
    struct test_tls_crypt_context *ctx = (struct test_tls_crypt_context *) *state;

    skip_if_tls_crypt_not_supported(ctx);

    ctx->co.flags |= CO_IGNORE_PACKET_ID;

    assert_true(tls_crypt_wrap(&ctx->source, &ctx->ciphertext, &ctx->co));
    assert_true(BLEN(&ctx->source) < BLEN(&ctx->ciphertext));
    struct buffer tmp = ctx->ciphertext;
    assert_true(tls_crypt_unwrap(&tmp, &ctx->unwrapped, &ctx->co));
    buf_clear(&ctx->unwrapped);
    assert_true(tls_crypt_unwrap(&ctx->ciphertext, &ctx->unwrapped, &ctx->co));
}

struct test_tls_crypt_v2_context {
    struct gc_arena gc;
    struct key2 server_key2;
    struct key_ctx_bi server_keys;
    struct key2 client_key2;
    struct key_ctx_bi client_key;
    struct buffer metadata;
    struct buffer unwrapped_metadata;
    struct buffer wkc;
};

static int
test_tls_crypt_v2_setup(void **state) {
    struct test_tls_crypt_v2_context *ctx = calloc(1, sizeof(*ctx));
    *state = ctx;

    ctx->gc = gc_new();

    /* Sligthly longer buffers to be able to test too-long data */
    ctx->metadata = alloc_buf_gc(TLS_CRYPT_V2_MAX_METADATA_LEN+16, &ctx->gc);
    ctx->unwrapped_metadata = alloc_buf_gc(TLS_CRYPT_V2_MAX_METADATA_LEN+16,
                                           &ctx->gc);
    ctx->wkc = alloc_buf_gc(TLS_CRYPT_V2_MAX_WKC_LEN+16, &ctx->gc);

    /* Generate server key */
    rand_bytes((void *)ctx->server_key2.keys, sizeof(ctx->server_key2.keys));
    ctx->server_key2.n = 2;
    struct key_type kt = tls_crypt_kt();
    init_key_ctx_bi(&ctx->server_keys, &ctx->server_key2,
                    KEY_DIRECTION_BIDIRECTIONAL, &kt,
                    "tls-crypt-v2 server key");

    /* Generate client key */
    rand_bytes((void *)ctx->client_key2.keys, sizeof(ctx->client_key2.keys));
    ctx->client_key2.n = 2;

    return 0;
}

static int
test_tls_crypt_v2_teardown(void **state) {
    struct test_tls_crypt_v2_context *ctx =
            (struct test_tls_crypt_v2_context *) *state;

    free_key_ctx_bi(&ctx->server_keys);
    free_key_ctx_bi(&ctx->client_key);

    gc_free(&ctx->gc);

    free(ctx);

    return 0;
}

/**
 * Check wrapping and unwrapping a tls-crypt-v2 client key without metadata.
 */
static void
tls_crypt_v2_wrap_unwrap_no_metadata(void **state) {
    struct test_tls_crypt_v2_context *ctx =
            (struct test_tls_crypt_v2_context *) *state;

    struct buffer wrapped_client_key = alloc_buf_gc(TLS_CRYPT_V2_MAX_WKC_LEN,
                                                    &ctx->gc);
    assert_true(tls_crypt_v2_wrap_client_key(&wrapped_client_key,
                                             &ctx->client_key2,
                                             &ctx->metadata,
                                             &ctx->server_keys.encrypt,
                                             &ctx->gc));

    struct buffer unwrap_metadata = alloc_buf_gc(TLS_CRYPT_V2_MAX_METADATA_LEN,
                                                 &ctx->gc);
    struct key2 unwrapped_client_key2 = { 0 };
    assert_true(tls_crypt_v2_unwrap_client_key(&unwrapped_client_key2,
                                               &unwrap_metadata,
                                               wrapped_client_key,
                                               &ctx->server_keys.decrypt));

    assert_true(0 == memcmp(ctx->client_key2.keys, unwrapped_client_key2.keys,
                            sizeof(ctx->client_key2.keys)));
}

/**
 * Check wrapping and unwrapping a tls-crypt-v2 client key with maximum length
 * metadata.
 */
static void
tls_crypt_v2_wrap_unwrap_max_metadata(void **state) {
    struct test_tls_crypt_v2_context *ctx =
            (struct test_tls_crypt_v2_context *) *state;

    uint8_t* metadata =
            buf_write_alloc(&ctx->metadata, TLS_CRYPT_V2_MAX_METADATA_LEN);
    assert_true(rand_bytes(metadata, TLS_CRYPT_V2_MAX_METADATA_LEN));
    assert_true(tls_crypt_v2_wrap_client_key(&ctx->wkc, &ctx->client_key2,
                                             &ctx->metadata,
                                             &ctx->server_keys.encrypt,
                                             &ctx->gc));

    struct buffer unwrap_metadata = alloc_buf_gc(TLS_CRYPT_V2_MAX_METADATA_LEN,
                                                 &ctx->gc);
    struct key2 unwrapped_client_key2 = { 0 };
    assert_true(tls_crypt_v2_unwrap_client_key(&unwrapped_client_key2,
                                               &unwrap_metadata, ctx->wkc,
                                               &ctx->server_keys.decrypt));

    assert_true(0 == memcmp(ctx->client_key2.keys, unwrapped_client_key2.keys,
                            sizeof(ctx->client_key2.keys)));
    assert_true(buf_equal(&ctx->metadata, &unwrap_metadata));
}

/**
 * Check that wrapping a tls-crypt-v2 client key with too long metadata fails
 * as expected.
 */
static void
tls_crypt_v2_wrap_too_long_metadata(void **state) {
    struct test_tls_crypt_v2_context *ctx =
            (struct test_tls_crypt_v2_context *) *state;

    assert_true(buf_inc_len(&ctx->metadata, TLS_CRYPT_V2_MAX_METADATA_LEN+1));
    assert_false(tls_crypt_v2_wrap_client_key(&ctx->wkc, &ctx->client_key2,
                                              &ctx->metadata,
                                              &ctx->server_keys.encrypt,
                                              &ctx->gc));
}

/**
 * Check that unwrapping a tls-crypt-v2 client key with the wrong server key
 * fails as expected.
 */
static void
tls_crypt_v2_wrap_unwrap_wrong_key(void **state) {
    struct test_tls_crypt_v2_context *ctx =
            (struct test_tls_crypt_v2_context *) *state;

    assert_true(tls_crypt_v2_wrap_client_key(&ctx->wkc, &ctx->client_key2,
                                             &ctx->metadata,
                                             &ctx->server_keys.encrypt,
                                             &ctx->gc));

    /* Change server key */
    struct key_type kt = tls_crypt_kt();
    free_key_ctx_bi(&ctx->server_keys);
    memset(&ctx->server_key2.keys, 0, sizeof(ctx->server_key2.keys));
    init_key_ctx_bi(&ctx->server_keys, &ctx->server_key2,
                    KEY_DIRECTION_BIDIRECTIONAL, &kt,
                    "wrong tls-crypt-v2 server key");


    struct key2 unwrapped_client_key2 = { 0 };
    assert_false(tls_crypt_v2_unwrap_client_key(&unwrapped_client_key2,
                                                &ctx->unwrapped_metadata,
                                                ctx->wkc,
                                                &ctx->server_keys.decrypt));

    const struct key2 zero = { 0 };
    assert_true(0 == memcmp(&unwrapped_client_key2, &zero, sizeof(zero)));
    assert_true(0 == BLEN(&ctx->unwrapped_metadata));
}

/**
 * Check that unwrapping a tls-crypt-v2 client key to a too small metadata
 * buffer fails as expected.
 */
static void
tls_crypt_v2_wrap_unwrap_dst_too_small(void **state) {
    struct test_tls_crypt_v2_context *ctx =
            (struct test_tls_crypt_v2_context *) *state;

    uint8_t* metadata =
            buf_write_alloc(&ctx->metadata, TLS_CRYPT_V2_MAX_METADATA_LEN);
    assert_true(rand_bytes(metadata, TLS_CRYPT_V2_MAX_METADATA_LEN));
    assert_true(tls_crypt_v2_wrap_client_key(&ctx->wkc, &ctx->client_key2,
                                             &ctx->metadata,
                                             &ctx->server_keys.encrypt,
                                             &ctx->gc));

    struct key2 unwrapped_client_key2 = { 0 };
    struct buffer unwrapped_metadata =
            alloc_buf_gc(TLS_CRYPT_V2_MAX_METADATA_LEN-1, &ctx->gc);
    assert_false(tls_crypt_v2_unwrap_client_key(&unwrapped_client_key2,
                                                &unwrapped_metadata, ctx->wkc,
                                                &ctx->server_keys.decrypt));

    const struct key2 zero = { 0 };
    assert_true(0 == memcmp(&unwrapped_client_key2, &zero, sizeof(zero)));
    assert_true(0 == BLEN(&ctx->unwrapped_metadata));
}

int
main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(tls_crypt_loopback,
                                        test_tls_crypt_setup,
                                        test_tls_crypt_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_loopback_zero_len,
                                        test_tls_crypt_setup,
                                        test_tls_crypt_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_loopback_max_len,
                                        test_tls_crypt_setup,
                                        test_tls_crypt_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_fail_msg_too_long,
                                        test_tls_crypt_setup,
                                        test_tls_crypt_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_fail_invalid_key,
                                        test_tls_crypt_setup,
                                        test_tls_crypt_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_fail_replay,
                                        test_tls_crypt_setup,
                                        test_tls_crypt_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_ignore_replay,
                                        test_tls_crypt_setup,
                                        test_tls_crypt_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_v2_wrap_unwrap_no_metadata,
                                        test_tls_crypt_v2_setup,
                                        test_tls_crypt_v2_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_v2_wrap_unwrap_max_metadata,
                                        test_tls_crypt_v2_setup,
                                        test_tls_crypt_v2_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_v2_wrap_too_long_metadata,
                                        test_tls_crypt_v2_setup,
                                        test_tls_crypt_v2_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_v2_wrap_unwrap_wrong_key,
                                        test_tls_crypt_v2_setup,
                                        test_tls_crypt_v2_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_v2_wrap_unwrap_dst_too_small,
                                        test_tls_crypt_v2_setup,
                                        test_tls_crypt_v2_teardown),
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
