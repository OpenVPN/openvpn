/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 * Copyright (C) 2023-2024 OpenVPN Inc <sales@openvpn.net>
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

#include "crypto.h"
#include "options.h"
#include "ssl_backend.h"
#include "options_util.h"

#include "mock_msg.h"
#include "mss.h"
#include "ssl_verify_backend.h"
#include "win32.h"
#include "test_common.h"
#include "ssl.h"
#include "buffer.h"
#include "packet_id.h"

/* Mock function to be allowed to include win32.c which is required for
 * getting the temp directory */
#ifdef _WIN32
struct signal_info siginfo_static; /* GLOBAL */

const char *
strerror_win32(DWORD errnum, struct gc_arena *gc)
{
    ASSERT(false);
}

void
throw_signal(const int signum)
{
    ASSERT(false);
}
#endif

#if defined(ENABLE_CRYPTO_OPENSSL) && (OPENSSL_VERSION_NUMBER > 0x30000000L)
#define HAVE_OPENSSL_STORE
#endif

/* stubs for some unused functions instead of pulling in too many dependencies */
bool
get_user_pass_cr(struct user_pass *up, const char *auth_file, const char *prefix,
                 const unsigned int flags, const char *auth_challenge)
{
    return false;
}
void
purge_user_pass(struct user_pass *up, bool force)
{
    return;
}

static const char *const unittest_cert =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDYzCCAkugAwIBAgIRALrXTx4lqa8QgF7uGjISxmcwDQYJKoZIhvcNAQELBQAw\n"
    "GDEWMBQGA1UEAwwNT1ZQTiBURVNUIENBMTAgFw0yMzAzMTMxNjA5MThaGA8yMTIz\n"
    "MDIxNzE2MDkxOFowGTEXMBUGA1UEAwwOb3Zwbi10ZXN0LXJzYTEwggEiMA0GCSqG\n"
    "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7xFoR6fmoyfsJIQDKKgbYgFw0MzVuDAmp\n"
    "Rx6KTEihgTchkQx9fHddWbKiOUbcEnQi3LNux7P4QVl/4dRR3skisBug6Vd5LXeB\n"
    "GZqmpu5XZiF4DgLz1lX21G0aOogFWkie2qGEcso40159x9FBDl5A3sLP18ubeex0\n"
    "pd/BzDFv6SLOTyVWO/GCNc8IX/i0uN4mLvoVU00SeqwTPnS+CRXrSq4JjGDJLsXl\n"
    "0/PlxkjsgU0yOOA0Z2d8Fzk3wClwP6Hc49BOMWKstUIhLbG2DcIv8l29EuEj2w3j\n"
    "u/7gkewol96XQ2twpPvpoVAaiVh/m7hQUcQORQCD6eJcDjOZVCArAgMBAAGjgaQw\n"
    "gaEwCQYDVR0TBAIwADAdBgNVHQ4EFgQUqYnRaBHrZmKLtMZES5AuwqzJkGYwUwYD\n"
    "VR0jBEwwSoAU3MLDNDOK13DqflQ8ra7FeGBXK06hHKQaMBgxFjAUBgNVBAMMDU9W\n"
    "UE4gVEVTVCBDQTGCFD55ErHXpK2JXS3WkfBm0NB1r3vKMBMGA1UdJQQMMAoGCCsG\n"
    "AQUFBwMCMAsGA1UdDwQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAZVcXrezA9Aby\n"
    "sfUNHAsMxrex/EO0PrIPSrmSmc9sCiD8cCIeB6kL8c5iPPigoWW0uLA9zteDRFes\n"
    "ez+Z8wBY6g8VQ0tFPURDooUg5011GZPDcuw7/PsI4+I2J9q6LHEp+6Oo4faSn/kl\n"
    "yWYCLjM4FZdGXbOijDacQJiN6HcRv0UdodBrEVRf7YHJJmMCbCI7ZUGW2zef/+rO\n"
    "e4Lkxh0MLYqCkNKH5ZfoGTC4Oeb0xKykswAanqgR60r+upaLU8PFuI2L9M3vc6KU\n"
    "F6MgVGSxl6eylJgDYckvJiAbmcp2PD/LRQQOxQA0yqeAMg2cbdvclETuYD6zoFfu\n"
    "Y8aO7dvDlw==\n"
    "-----END CERTIFICATE-----\n";

static const char *const unittest_key =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC7xFoR6fmoyfsJ\n"
    "IQDKKgbYgFw0MzVuDAmpRx6KTEihgTchkQx9fHddWbKiOUbcEnQi3LNux7P4QVl/\n"
    "4dRR3skisBug6Vd5LXeBGZqmpu5XZiF4DgLz1lX21G0aOogFWkie2qGEcso40159\n"
    "x9FBDl5A3sLP18ubeex0pd/BzDFv6SLOTyVWO/GCNc8IX/i0uN4mLvoVU00SeqwT\n"
    "PnS+CRXrSq4JjGDJLsXl0/PlxkjsgU0yOOA0Z2d8Fzk3wClwP6Hc49BOMWKstUIh\n"
    "LbG2DcIv8l29EuEj2w3ju/7gkewol96XQ2twpPvpoVAaiVh/m7hQUcQORQCD6eJc\n"
    "DjOZVCArAgMBAAECggEACqkuWAAJ3cyCBVWrXs8eDmLTWV9i9DmYvtS75ixIn2rf\n"
    "v3cl12YevN0f6FgKLuqZT3Vqdqq+DCVhuIIQ9QkKMH8BQpSdE9NCCsFyZ23o8Gtr\n"
    "EQ7ymfecb+RFwYx7NpqWrvZI32VJGArgPZH/zorLTTGYrAZbmBtHEqRsXOuEDw97\n"
    "slwwcWaa9ztaYC8/N/7fgsnydaCFSaOByRlWuyvSmHvn6ZwLv8ANOshY6fstC0Jb\n"
    "BW0GpSe9eZPjpl71VT2RtpghqLV5+iAoFDHoT+eZvBospcUGtfcZSU7RrBjKB8+a\n"
    "U1d6hwKhduVs2peIQzl+FiOSdWriLcsZv79q4sBhsQKBgQDUDVTf5BGJ8apOs/17\n"
    "YVk+Ad8Ey8sXvsfk49psmlCRa8Z4g0LVXfrP94qzhtl8U5kE9hs3nEF4j/kX1ZWG\n"
    "k11tdsNTZN5x5bbAgEgPA6Ap6J/uto0HS8G0vSv0lyBymdKA3p/i5Dx+8Nc9cGns\n"
    "LGI9MvviLX7pQFIkvbaCkdKwYwKBgQDirowjWZnm7BgVhF0G1m3DY9nQTYYU185W\n"
    "UESaO5/nVzwUrA+FypJamD+AvmlSuY8rJeQAGAS6nQr9G8/617r+GwJnzRtxC6Vl\n"
    "4OF5BJRsD70oX4CFOOlycMoJ8tzcYVH7NI8KVocjxb+QW82hqSvEwSsvnwwn3eOW\n"
    "nr5u5vIHmQKBgCuc3lL6Dl1ntdZgEIdau0cUjXDoFUo589TwxBDIID/4gaZxoMJP\n"
    "hPFXAVDxMDPw4azyjSB/47tPKTUsuYcnMfT8kynIujOEwnSPLcLgxQU5kgM/ynuw\n"
    "qhNpQOwaVRMc7f2RTCMXPBYDpNE/GJn5eu8JWGLpZovEreBeoHX0VffvAoGAVrWn\n"
    "+3mxykhzaf+oyg3KDNysG+cbq+tlDVVE+K5oG0kePVYX1fjIBQmJ+QhdJ3y9jCbB\n"
    "UVveqzeZVXqHEw/kgoD4aZZmsdZfnVnpRa5/y9o1ZDUr50n+2nzUe/u/ijlb77iK\n"
    "Is04gnGJNoI3ZWhdyrSNfXjcYH+bKClu9OM4n7kCgYAorc3PAX7M0bsQrrqYxUS8\n"
    "56UU0YdhAgYitjM7Fm/0iIm0vDpSevxL9js4HnnsSMVR77spCBAGOCCZrTcI3Ejg\n"
    "xKDYzh1xlfMRjJBuBu5Pd55ZAv9NXFGpsX5SO8fDZQJMwpcbQH36+UdqRRFDpjJ0\n"
    "ZbX6nKcJ7jciJVKJds59Jg==\n"
    "-----END PRIVATE KEY-----\n";

static const char *
get_tmp_dir(void)
{
    const char *ret;
#ifdef _WIN32
    ret = win_get_tempdir();
#else
    ret = "/tmp";
#endif
    assert_non_null(ret);
    return ret;
}

static struct
{
    struct gc_arena gc;
    const char *certfile;
    const char *keyfile;
} global_state;

static int
init(void **state)
{
    (void) state;
    global_state.gc = gc_new();
    global_state.certfile = platform_create_temp_file(get_tmp_dir(), "cert", &global_state.gc);
    global_state.keyfile = platform_create_temp_file(get_tmp_dir(), "key", &global_state.gc);

    int certfd = open(global_state.certfile, O_RDWR);
    int keyfd = open(global_state.keyfile, O_RDWR);
    if (certfd < 0 || keyfd < 0)
    {
        fail_msg("make tmpfile for certificate or key data failed (error = %d)", errno);
    }
    assert_int_equal(write(certfd, unittest_cert, strlen(unittest_cert)), strlen(unittest_cert));
    assert_int_equal(write(keyfd, unittest_key, strlen(unittest_key)), strlen(unittest_key));
    close(certfd);
    close(keyfd);
    return 0;
}

static int
cleanup(void **state)
{
    (void) state;
    unlink(global_state.certfile);
    unlink(global_state.keyfile);
    gc_free(&global_state.gc);
    return 0;
}

static void
crypto_pem_encode_certificate(void **state)
{
    struct gc_arena gc = gc_new();

    struct tls_root_ctx ctx = { 0 };
    tls_ctx_client_new(&ctx);
    tls_ctx_load_cert_file(&ctx, unittest_cert, true);

    openvpn_x509_cert_t *cert = NULL;

    /* we do not have methods to fetch certificates from ssl contexts, use
     * internal TLS library methods for the unit test */
#ifdef ENABLE_CRYPTO_OPENSSL
    cert = SSL_CTX_get0_certificate(ctx.ctx);
#elif defined(ENABLE_CRYPTO_MBEDTLS)
    cert = ctx.crt_chain;
#endif

    const char *tmpfile = platform_create_temp_file(get_tmp_dir(), "ut_pem", &gc);
    backend_x509_write_pem(cert, tmpfile);

    struct buffer exported_pem = buffer_read_from_file(tmpfile, &gc);
    assert_string_equal(BSTR(&exported_pem), unittest_cert);

    tls_ctx_free(&ctx);
    unlink(tmpfile);
    gc_free(&gc);
}

static void
test_load_certificate_and_key(void **state)
{
    (void) state;
    struct tls_root_ctx ctx = { 0 };

    /* test loading of inlined cert and key.
     * loading the key also checks that it matches the loaded certificate
     */
    tls_ctx_client_new(&ctx);
    tls_ctx_load_cert_file(&ctx, unittest_cert, true);
    assert_int_equal(tls_ctx_load_priv_file(&ctx, unittest_key, true), 0);
    tls_ctx_free(&ctx);

    /* test loading of cert and key from file */
    tls_ctx_client_new(&ctx);
    tls_ctx_load_cert_file(&ctx, global_state.certfile, false);
    assert_int_equal(tls_ctx_load_priv_file(&ctx, global_state.keyfile, false), 0);
    tls_ctx_free(&ctx);
}

/* test loading cert and key using file:/path URI */
static void
test_load_certificate_and_key_uri(void **state)
{
    (void) state;

#if !defined(HAVE_OPENSSL_STORE)
    skip();
#else /* HAVE_OPENSSL_STORE */

    struct tls_root_ctx ctx = { 0 };
    const char *certfile = global_state.certfile;
    const char *keyfile = global_state.keyfile;
    struct gc_arena *gc = &global_state.gc;

    struct buffer certuri = alloc_buf_gc(6 + strlen(certfile) + 1, gc); /* 6 bytes for "file:/" */
    struct buffer keyuri = alloc_buf_gc(6 + strlen(keyfile) + 1, gc);   /* 6 bytes for "file:/" */

    /* Windows temp file path starts with drive letter -- add a leading slash for URI */
    const char *lead = "";
#ifdef _WIN32
    lead = "/";
#endif /* _WIN32 */
    assert_true(buf_printf(&certuri, "file:%s%s", lead, certfile));
    assert_true(buf_printf(&keyuri, "file:%s%s", lead, keyfile));

    /* On Windows replace any '\' in path by '/' required for URI */
#ifdef _WIN32
    string_mod(BSTR(&certuri), CC_ANY, CC_BACKSLASH, '/');
    string_mod(BSTR(&keyuri), CC_ANY, CC_BACKSLASH, '/');
#endif /* _WIN32 */

    tls_ctx_client_new(&ctx);
    tls_ctx_load_cert_file(&ctx, BSTR(&certuri), false);
    assert_int_equal(tls_ctx_load_priv_file(&ctx, BSTR(&keyuri), false), 0);
    tls_ctx_free(&ctx);
#endif /* HAVE_OPENSSL_STORE */
}


static void
init_frame_parameters(struct frame *frame)
{
    int overhead = 0;

    /* tls-auth and tls-crypt */
    overhead += 128;

    /* TCP length field and opcode */
    overhead += 3;

    /* ACK array and remote SESSION ID (part of the ACK array) */
    overhead += ACK_SIZE(RELIABLE_ACK_SIZE);

    /* Previous OpenVPN version calculated the maximum size and buffer of a
     * control frame depending on the overhead of the data channel frame
     * overhead and limited its maximum size to 1250. Since control frames
     * also need to fit into data channel buffer we have the same
     * default of 1500 + 100 as data channel buffers have. Increasing
     * control channel mtu beyond this limit also increases the data channel
     * buffers */
    int tls_mtu = 1500;
    frame->buf.payload_size = tls_mtu + 100;

    frame->buf.headroom = overhead;
    frame->buf.tailroom = overhead;

    frame->tun_mtu = tls_mtu;

}

static void
do_data_channel_round_trip(struct crypto_options *co)
{
    struct gc_arena gc = gc_new();

    /* initialise frame for the test */
    struct frame frame;
    init_frame_parameters(&frame);

    struct buffer src = alloc_buf_gc(frame.buf.payload_size, &gc);
    struct buffer work = alloc_buf_gc(BUF_SIZE(&frame), &gc);
    struct buffer encrypt_workspace = alloc_buf_gc(BUF_SIZE(&frame), &gc);
    struct buffer decrypt_workspace = alloc_buf_gc(BUF_SIZE(&frame), &gc);
    struct buffer buf = clear_buf();
    void *buf_p;

    /* init work */
    ASSERT(buf_init(&work, frame.buf.headroom));

    update_time();

    /* Test encryption, decryption for all packet sizes */
    for (int i = 1; i <= frame.buf.payload_size; ++i)
    {

        /* msg(M_INFO, "TESTING ENCRYPT/DECRYPT of packet length=%d", i); */

        /*
         * Load src with random data.
         */
        ASSERT(buf_init(&src, 0));
        ASSERT(i <= src.capacity);
        src.len = i;
        ASSERT(rand_bytes(BPTR(&src), BLEN(&src)));

        /* copy source to input buf */
        buf = work;
        buf_p = buf_write_alloc(&buf, BLEN(&src));
        ASSERT(buf_p);
        memcpy(buf_p, BPTR(&src), BLEN(&src));

        /* initialize work buffer with buf.headroom bytes of prepend capacity */
        ASSERT(buf_init(&encrypt_workspace, frame.buf.headroom));

        /* encrypt */
        openvpn_encrypt(&buf, encrypt_workspace, co);

        /* decrypt */
        openvpn_decrypt(&buf, decrypt_workspace, co, &frame, BPTR(&buf));

        /* compare */
        assert_int_equal(buf.len, src.len);
        assert_memory_equal(BPTR(&src), BPTR(&buf), i);

    }
    gc_free(&gc);
}



struct crypto_options
init_crypto_options(const char *cipher, const char *auth)
{
    struct key2 key2 = { .n = 2};

    ASSERT(rand_bytes(key2.keys[0].cipher, sizeof(key2.keys[0].cipher)));
    ASSERT(rand_bytes(key2.keys[0].hmac, sizeof(key2.keys[0].hmac)));
    ASSERT(rand_bytes(key2.keys[1].cipher, sizeof(key2.keys[1].cipher)));
    ASSERT(rand_bytes(key2.keys[1].hmac, sizeof(key2.keys)[1].hmac));

    struct crypto_options co = { 0 };

    struct key_type kt = create_kt(cipher, auth, "ssl-test");

    init_key_ctx_bi(&co.key_ctx_bi, &key2, 0, &kt, "unit-test-ssl");
    packet_id_init(&co.packet_id,  5, 5, "UNITTEST", 0);

    return co;
}

static void
uninit_crypto_options(struct crypto_options *co)
{
    packet_id_free(&co->packet_id);
    free_key_ctx_bi(&co->key_ctx_bi);

}

/* This adds a few more methods than strictly necessary but this allows
 * us to see which exact test was run from the backtrace of the test
 * when it fails */
static void
run_data_channel_with_cipher_end(const char *cipher)
{
    struct crypto_options co = init_crypto_options(cipher, "none");
    co.flags |= CO_EPOCH_DATA_KEY_FORMAT;
    do_data_channel_round_trip(&co);
    uninit_crypto_options(&co);
}

static void
run_data_channel_with_cipher(const char *cipher, const char *auth)
{
    struct crypto_options co = init_crypto_options(cipher, auth);
    do_data_channel_round_trip(&co);
    uninit_crypto_options(&co);
}


static void
test_data_channel_roundtrip_aes_128_gcm(void **state)
{
    run_data_channel_with_cipher_end("AES-128-GCM");
    run_data_channel_with_cipher("AES-128-GCM", "none");
}

static void
test_data_channel_roundtrip_aes_192_gcm(void **state)
{
    run_data_channel_with_cipher_end("AES-192-GCM");
    run_data_channel_with_cipher("AES-192-GCM", "none");
}

static void
test_data_channel_roundtrip_aes_256_gcm(void **state)
{
    run_data_channel_with_cipher_end("AES-256-GCM");
    run_data_channel_with_cipher("AES-256-GCM", "none");
}

static void
test_data_channel_roundtrip_aes_128_cbc(void **state)
{
    run_data_channel_with_cipher("AES-128-CBC", "SHA256");
}

static void
test_data_channel_roundtrip_aes_192_cbc(void **state)
{
    run_data_channel_with_cipher("AES-192-CBC", "SHA256");
}

static void
test_data_channel_roundtrip_aes_256_cbc(void **state)
{
    run_data_channel_with_cipher("AES-256-CBC", "SHA256");
}

static void
test_data_channel_roundtrip_chacha20_poly1305(void **state)
{
    if (!cipher_valid("ChaCha20-Poly1305"))
    {
        skip();
        return;
    }

    run_data_channel_with_cipher_end("ChaCha20-Poly1305");
    run_data_channel_with_cipher("ChaCha20-Poly1305", "none");
}

static void
test_data_channel_roundtrip_bf_cbc(void **state)
{
    if (!cipher_valid("BF-CBC"))
    {
        skip();
        return;
    }
    run_data_channel_with_cipher("BF-CBC", "SHA1");
}


int
main(void)
{
    openvpn_unit_test_setup();

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(crypto_pem_encode_certificate),
        cmocka_unit_test(test_load_certificate_and_key),
        cmocka_unit_test(test_load_certificate_and_key_uri),
        cmocka_unit_test(test_data_channel_roundtrip_aes_128_gcm),
        cmocka_unit_test(test_data_channel_roundtrip_aes_192_gcm),
        cmocka_unit_test(test_data_channel_roundtrip_aes_256_gcm),
        cmocka_unit_test(test_data_channel_roundtrip_chacha20_poly1305),
        cmocka_unit_test(test_data_channel_roundtrip_aes_128_cbc),
        cmocka_unit_test(test_data_channel_roundtrip_aes_192_cbc),
        cmocka_unit_test(test_data_channel_roundtrip_aes_256_cbc),
        cmocka_unit_test(test_data_channel_roundtrip_bf_cbc),
    };

#if defined(ENABLE_CRYPTO_OPENSSL)
    tls_init_lib();
#endif

    int ret = cmocka_run_group_tests_name("ssl tests", tests, init, cleanup);

#if defined(ENABLE_CRYPTO_OPENSSL)
    tls_free_lib();
#endif

    return ret;
}
