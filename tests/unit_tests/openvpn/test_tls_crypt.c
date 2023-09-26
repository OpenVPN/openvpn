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

#include "tls_crypt.c"

#include "mock_msg.h"

/* Define this function here as dummy since including the ssl_*.c files
 * leads to having to include even more unrelated code */
bool
key_state_export_keying_material(struct tls_session *session,
                                 const char *label, size_t label_size,
                                 void *ekm, size_t ekm_size)
{
    memset(ekm, 0xba, ekm_size);
    return true;
}


#define TESTBUF_SIZE            128

/* Defines for use in the tests and the mock parse_line() */
#define PATH1       "/s p a c e"
#define PATH2       "/foo bar/baz"
#define PARAM1      "param1"
#define PARAM2      "param two"

static const char *test_server_key = \
    "-----BEGIN OpenVPN tls-crypt-v2 server key-----\n"
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\n"
    "MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f\n"
    "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8=\n"
    "-----END OpenVPN tls-crypt-v2 server key-----\n";

static const char *test_client_key = \
    "-----BEGIN OpenVPN tls-crypt-v2 client key-----\n"
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\n"
    "MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f\n"
    "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P\n"
    "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/\n"
    "wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v\n"
    "8PHy8/T19vf4+fr7/P3+/xd9pcB0qUYZsWvkrLcfGmzPJPM8a7r0mEWdXwbDadSV\n"
    "LHg5bv2TwlmPR3HgaMr8o9LTh9hxUTkrH3S0PfKRNwcso86ua/dBFTyXsM9tg4aw\n"
    "3dS6ogH9AkaT+kRRDgNcKWkQCbwmJK2JlfkXHBwbAtmn78AkNuho6QCFqCdqGab3\n"
    "zh2vheFqGMPdGpukbFrT3rcO3VLxUeG+RdzXiMTCpJSovFBP1lDkYwYJPnz6daEh\n"
    "j0TzJ3BVru9W3CpotdNt7u09knxAfpCxjtrP3semsDew/gTBtcfQ/OoTFyFHnN5k\n"
    "RZ+q17SC4nba3Pp8/Fs0+hSbv2tJozoD8SElFq7SIWJsciTYh8q8f5yQxjdt4Wxu\n"
    "/Z5wtPCAZ0tOzj4ItTI77fBOYRTfEayzHgEr\n"
    "-----END OpenVPN tls-crypt-v2 client key-----\n";


/* Has custom metadata of AABBCCDD (base64) */
static const char *test_client_key_metadata = \
    "-----BEGIN OpenVPN tls-crypt-v2 client key-----\n"
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\n"
    "MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f\n"
    "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P\n"
    "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/\n"
    "wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v\n"
    "8PHy8/T19vf4+fr7/P3+/2ntp1WCqhcLjJQY/igkjNt3Yb6i0neqFkfrOp2UCDcz\n"
    "6RSJtPLZbvOOKUHk2qwxPYUsFCnz/IWV6/ZiLRrabzUpS8oSN1HS6P7qqAdrHKgf\n"
    "hVTHasdSf2UdMTPC7HBgnP9Ll0FhKN0h7vSzbbt7QM7wH9mr1ecc/Mt0SYW2lpwA\n"
    "aJObYGTyk6hTgWm0g/MLrworLrezTqUHBZzVsu+LDyqLWK1lzJNd66MuNOsGA4YF\n"
    "fbCsDh8n3H+Cw1k5YNBZDYYJOtVUgBWXheO6vgoOmqDdI0dAQ3hVo9DE+SkCFjgf\n"
    "l4FY2yLEh9ZVZZrl1eD1Owh/X178CkHrBJYl9LNQSyQEKlDGWwBLQ/pY3qtjctr3\n"
    "pV62MPQdBo+1lcsjDCJVQA6XUyltas4BKQ==\n"
    "-----END OpenVPN tls-crypt-v2 client key-----\n";

int
__wrap_parse_line(const char *line, char **p, const int n, const char *file,
                  const int line_num, int msglevel, struct gc_arena *gc)
{
    p[0] = PATH1 PATH2;
    p[1] = PARAM1;
    p[2] = PARAM2;
    return 3;
}

bool
__wrap_buffer_write_file(const char *filename, const struct buffer *buf)
{
    const char *pem = BSTR(buf);
    check_expected(filename);
    check_expected(pem);

    return mock_type(bool);
}

struct buffer
__wrap_buffer_read_from_file(const char *filename, struct gc_arena *gc)
{
    check_expected(filename);

    const char *pem_str = mock_ptr_type(const char *);
    struct buffer ret = alloc_buf_gc(strlen(pem_str) + 1, gc);
    buf_write(&ret, pem_str, strlen(pem_str) + 1);

    return ret;
}


/** Predictable random for tests */
int
__wrap_rand_bytes(uint8_t *output, int len)
{
    for (int i = 0; i < len; i++)
    {
        output[i] = i;
    }
    return true;
}

struct test_tls_crypt_context {
    struct crypto_options co;
    struct key_type kt;
    struct buffer source;
    struct buffer ciphertext;
    struct buffer unwrapped;
};


static int
test_tls_crypt_setup(void **state)
{
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
    const char *plaintext = "1234567890";
    buf_write(&ctx->source, plaintext, strlen(plaintext));

    /* Write test ciphertext */
    const char *ciphertext = "012345678";
    buf_write(&ctx->ciphertext, ciphertext, strlen(ciphertext));

    return 0;
}

static int
test_tls_crypt_teardown(void **state)
{
    struct test_tls_crypt_context *ctx =
        (struct test_tls_crypt_context *)*state;

    free_buf(&ctx->source);
    free_buf(&ctx->ciphertext);
    free_buf(&ctx->unwrapped);

    free_key_ctx_bi(&ctx->co.key_ctx_bi);

    free(ctx);

    return 0;
}

static void
skip_if_tls_crypt_not_supported(struct test_tls_crypt_context *ctx)
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
tls_crypt_loopback(void **state)
{
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
 * Test generating dynamic tls-crypt key
 */
static void
test_tls_crypt_secure_reneg_key(void **state)
{
    struct test_tls_crypt_context *ctx =
        (struct test_tls_crypt_context *)*state;

    struct gc_arena gc = gc_new();

    struct tls_multi multi = { 0 };
    struct tls_session session = { 0 };

    struct tls_options tls_opt = { 0 };
    tls_opt.replay_window = 32;
    tls_opt.replay_time = 60;
    tls_opt.frame.buf.payload_size = 512;
    session.opt = &tls_opt;

    tls_session_generate_dynamic_tls_crypt_key(&multi, &session);

    struct tls_wrap_ctx *rctx = &session.tls_wrap_reneg;

    tls_crypt_wrap(&ctx->source, &rctx->work, &rctx->opt);
    assert_int_equal(buf_len(&ctx->source) + 40, buf_len(&rctx->work));

    uint8_t expected_ciphertext[] = {
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xe3, 0x19, 0x27, 0x7f, 0x1c, 0x8d, 0x6e, 0x6a,
        0x77, 0x96, 0xa8, 0x55, 0x33, 0x7b, 0x9c, 0xfb, 0x56, 0xe1, 0xf1, 0x3a, 0x87, 0x0e, 0x66, 0x47,
        0xdf, 0xa1, 0x95, 0xc9, 0x2c, 0x17, 0xa0, 0x15, 0xba, 0x49, 0x67, 0xa1, 0x1d, 0x55, 0xea, 0x1a,
        0x06, 0xa7
    };
    assert_memory_equal(BPTR(&rctx->work), expected_ciphertext, buf_len(&rctx->work));
    tls_wrap_free(&session.tls_wrap_reneg);

    /* Use previous tls-crypt key as 0x00, with xor we should have the same key
     * and expect the same result */
    session.tls_wrap.mode = TLS_WRAP_CRYPT;
    memset(&session.tls_wrap.original_wrap_keydata.keys, 0x00, sizeof(session.tls_wrap.original_wrap_keydata.keys));
    session.tls_wrap.original_wrap_keydata.n = 2;

    tls_session_generate_dynamic_tls_crypt_key(&multi, &session);
    tls_crypt_wrap(&ctx->source, &rctx->work, &rctx->opt);
    assert_int_equal(buf_len(&ctx->source) + 40, buf_len(&rctx->work));

    assert_memory_equal(BPTR(&rctx->work), expected_ciphertext, buf_len(&rctx->work));
    tls_wrap_free(&session.tls_wrap_reneg);

    /* XOR should not force a different key */
    memset(&session.tls_wrap.original_wrap_keydata.keys, 0x42, sizeof(session.tls_wrap.original_wrap_keydata.keys));
    tls_session_generate_dynamic_tls_crypt_key(&multi, &session);

    tls_crypt_wrap(&ctx->source, &rctx->work, &rctx->opt);
    assert_int_equal(buf_len(&ctx->source) + 40, buf_len(&rctx->work));

    /* packet id at the start should be equal */
    assert_memory_equal(BPTR(&rctx->work), expected_ciphertext, 8);

    /* Skip packet id */
    buf_advance(&rctx->work, 8);
    assert_memory_not_equal(BPTR(&rctx->work), expected_ciphertext, buf_len(&rctx->work));
    tls_wrap_free(&session.tls_wrap_reneg);


    gc_free(&gc);
}

/**
 * Check that zero-byte messages are successfully wrapped-and-unwrapped.
 */
static void
tls_crypt_loopback_zero_len(void **state)
{
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
tls_crypt_loopback_max_len(void **state)
{
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
tls_crypt_fail_msg_too_long(void **state)
{
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
tls_crypt_fail_invalid_key(void **state)
{
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
tls_crypt_fail_replay(void **state)
{
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
tls_crypt_ignore_replay(void **state)
{
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
test_tls_crypt_v2_setup(void **state)
{
    struct test_tls_crypt_v2_context *ctx = calloc(1, sizeof(*ctx));
    *state = ctx;

    ctx->gc = gc_new();

    /* Slightly longer buffers to be able to test too-long data */
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
test_tls_crypt_v2_teardown(void **state)
{
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
tls_crypt_v2_wrap_unwrap_no_metadata(void **state)
{
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
tls_crypt_v2_wrap_unwrap_max_metadata(void **state)
{
    struct test_tls_crypt_v2_context *ctx =
        (struct test_tls_crypt_v2_context *) *state;

    uint8_t *metadata =
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

    struct tls_wrap_ctx wrap_ctx = {
        .mode = TLS_WRAP_CRYPT,
        .tls_crypt_v2_server_key = ctx->server_keys.encrypt,
    };
    assert_true(tls_crypt_v2_extract_client_key(&ctx->wkc, &wrap_ctx, NULL));
    tls_wrap_free(&wrap_ctx);
}

/**
 * Check that wrapping a tls-crypt-v2 client key with too long metadata fails
 * as expected.
 */
static void
tls_crypt_v2_wrap_too_long_metadata(void **state)
{
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
tls_crypt_v2_wrap_unwrap_wrong_key(void **state)
{
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
tls_crypt_v2_wrap_unwrap_dst_too_small(void **state)
{
    struct test_tls_crypt_v2_context *ctx =
        (struct test_tls_crypt_v2_context *) *state;

    uint8_t *metadata =
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

static void
test_tls_crypt_v2_write_server_key_file(void **state)
{
    const char *filename = "testfilename.key";

    expect_string(__wrap_buffer_write_file, filename, filename);
    expect_memory(__wrap_buffer_write_file, pem, test_server_key,
                  strlen(test_server_key));
    will_return(__wrap_buffer_write_file, true);

    tls_crypt_v2_write_server_key_file(filename);
}

static void
test_tls_crypt_v2_write_client_key_file(void **state)
{
    const char *filename = "testfilename.key";

    /* Test writing the client key */
    expect_string(__wrap_buffer_write_file, filename, filename);
    expect_memory(__wrap_buffer_write_file, pem, test_client_key,
                  strlen(test_client_key));
    will_return(__wrap_buffer_write_file, true);

    /* Key generation re-reads the created file as a sanity check */
    expect_string(__wrap_buffer_read_from_file, filename, filename);
    will_return(__wrap_buffer_read_from_file, test_client_key);

    tls_crypt_v2_write_client_key_file(filename, NULL, test_server_key, true);
}

static void
test_tls_crypt_v2_write_client_key_file_metadata(void **state)
{
    const char *filename = "testfilename.key";
    const char *b64metadata = "AABBCCDD";

    /* Test writing the client key */
    expect_string(__wrap_buffer_write_file, filename, filename);
    expect_memory(__wrap_buffer_write_file, pem, test_client_key_metadata,
                  strlen(test_client_key_metadata));
    will_return(__wrap_buffer_write_file, true);

    /* Key generation re-reads the created file as a sanity check */
    expect_string(__wrap_buffer_read_from_file, filename, filename);
    will_return(__wrap_buffer_read_from_file, test_client_key_metadata);

    tls_crypt_v2_write_client_key_file(filename, b64metadata, test_server_key,
                                       true);
}

int
main(void)
{
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
        cmocka_unit_test_setup_teardown(test_tls_crypt_secure_reneg_key,
                                        test_tls_crypt_setup,
                                        test_tls_crypt_teardown),
        cmocka_unit_test(test_tls_crypt_v2_write_server_key_file),
        cmocka_unit_test(test_tls_crypt_v2_write_client_key_file),
        cmocka_unit_test(test_tls_crypt_v2_write_client_key_file_metadata),
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
