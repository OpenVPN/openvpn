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


const char *unittest_cert = "-----BEGIN CERTIFICATE-----\n"
                            "MIIBuTCCAUCgAwIBAgIUTLtjSBzx53qZRvZ6Ur7D9kgoOHkwCgYIKoZIzj0EAwIw\n"
                            "EzERMA8GA1UEAwwIdW5pdHRlc3QwIBcNMjMxMTIxMDk1NDQ3WhgPMjA3ODA4MjQw\n"
                            "OTU0NDdaMBMxETAPBgNVBAMMCHVuaXR0ZXN0MHYwEAYHKoZIzj0CAQYFK4EEACID\n"
                            "YgAEHYB2hn2xx3f4lClXDtdi36P19pMZA+kI1Dkv/Vn10vBZ/j9oa+P99T8duz/e\n"
                            "QlPeHpesNJO4fX8iEDj6+vMeWejOT7jAQ4MmG5EZjpcBKxCfwFooEvzu8bVujUcu\n"
                            "wTQEo1MwUTAdBgNVHQ4EFgQUPcgBEVXjF5vYfDsInoE3dF6UfQswHwYDVR0jBBgw\n"
                            "FoAUPcgBEVXjF5vYfDsInoE3dF6UfQswDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjO\n"
                            "PQQDAgNnADBkAjBLPAGrQAyinigqiu0RomoV8TVaknVLFSq6H6A8jgvzfsFCUK1O\n"
                            "dvNZhFPM6idKB+oCME2JLOBANCSV8o7aJzq7SYHKwPyb1J4JFlwKe/0Jpv7oh9b1\n"
                            "IJbuaM9Z/VSKbrIXGg==\n"
                            "-----END CERTIFICATE-----\n";

static const char *
get_tmp_dir()
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
init_implicit_iv(struct crypto_options *co)
{
    cipher_ctx_t *cipher = co->key_ctx_bi.encrypt.cipher;

    if (cipher_ctx_mode_aead(cipher))
    {
        size_t impl_iv_len = cipher_ctx_iv_length(cipher) - sizeof(packet_id_type);
        ASSERT(cipher_ctx_iv_length(cipher) <= OPENVPN_MAX_IV_LENGTH);
        ASSERT(cipher_ctx_iv_length(cipher) >= OPENVPN_AEAD_MIN_IV_LEN);

        /* Generate dummy implicit IV */
        ASSERT(rand_bytes(co->key_ctx_bi.encrypt.implicit_iv,
                          OPENVPN_MAX_IV_LENGTH));
        co->key_ctx_bi.encrypt.implicit_iv_len = impl_iv_len;

        memcpy(co->key_ctx_bi.decrypt.implicit_iv,
               co->key_ctx_bi.encrypt.implicit_iv, OPENVPN_MAX_IV_LENGTH);
        co->key_ctx_bi.decrypt.implicit_iv_len = impl_iv_len;
    }
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

    init_implicit_iv(co);
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
    run_data_channel_with_cipher("AES-128-GCM", "none");
}

static void
test_data_channel_roundtrip_aes_192_gcm(void **state)
{
    run_data_channel_with_cipher("AES-192-GCM", "none");
}

static void
test_data_channel_roundtrip_aes_256_gcm(void **state)
{
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

    int ret = cmocka_run_group_tests_name("ssl tests", tests, NULL, NULL);

#if defined(ENABLE_CRYPTO_OPENSSL)
    tls_free_lib();
#endif

    return ret;
}
