/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 * Copyright (C) 2023-2025 OpenVPN Inc <sales@openvpn.net>
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

#include "crypto.h"
#include "crypto_epoch.h"
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

/* generated using
 * openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout - \
 * -noenc -sha256 -days 3650 -subj '/CN=ovpn-test-secp384r1'  -nodes \
 * -addext 'subjectAltName=DNS:unittest.example.com' \
 * -addext 'extendedKeyUsage=clientAuth'
 */
static const char *const unittest_cert =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICBjCCAYygAwIBAgIUFoXgpP4beykV7tpgrjHQTWPGi4cwCgYIKoZIzj0EAwIw\n"
    "HjEcMBoGA1UEAwwTb3Zwbi10ZXN0LXNlY3AzODRyMTAeFw0yNTA5MDgxMzExNTBa\n"
    "Fw0zNTA5MDYxMzExNTBaMB4xHDAaBgNVBAMME292cG4tdGVzdC1zZWNwMzg0cjEw\n"
    "djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQVDmf+TZB3rW6zqWFox606u/PhA93ysX/h\n"
    "1s2xyq9+QGzIdE/hks6p/Yzyu7RLOUjxvO0J45RHcYmo67DlvSOi496T3zrgvp1H\n"
    "KfHD5ohMyvzw0+e8lmjJqJjn+PegMkOjgYowgYcwHQYDVR0OBBYEFCH1eYnaV8fh\n"
    "E3Bv7lyrlYu24eoVMB8GA1UdIwQYMBaAFCH1eYnaV8fhE3Bv7lyrlYu24eoVMA8G\n"
    "A1UdEwEB/wQFMAMBAf8wHwYDVR0RBBgwFoIUdW5pdHRlc3QuZXhhbXBsZS5jb20w\n"
    "EwYDVR0lBAwwCgYIKwYBBQUHAwIwCgYIKoZIzj0EAwIDaAAwZQIxAL7q7jcwTOuq\n"
    "5sp0Beq81Vnznd3gsDZYNs1OYRWH33xergDVKlBb6kCwus0dhghtVAIwIgT4ytkY\n"
    "oAPx8LB3oP8ubEu1ue6V9jZln/cCiLyXDDtaiJOZHtDqHGfHqvc6rAok\n"
    "-----END CERTIFICATE-----\n";

static const char *const unittest_key =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAXBC7tpa9UepoMVZlM\n"
    "OxUubkECGK7aWFebxDc3UPoEQemEPMOCdkWBSU/t7Mm4R66hZANiAAQVDmf+TZB3\n"
    "rW6zqWFox606u/PhA93ysX/h1s2xyq9+QGzIdE/hks6p/Yzyu7RLOUjxvO0J45RH\n"
    "cYmo67DlvSOi496T3zrgvp1HKfHD5ohMyvzw0+e8lmjJqJjn+PegMkM=\n"
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
    (void)state;
    global_state.gc = gc_new();
    global_state.certfile = platform_create_temp_file(get_tmp_dir(), "cert", &global_state.gc);
    global_state.keyfile = platform_create_temp_file(get_tmp_dir(), "key", &global_state.gc);

    int certfd = open(global_state.certfile, O_RDWR);
    int keyfd = open(global_state.keyfile, O_RDWR);
    if (certfd < 0 || keyfd < 0)
    {
        fail_msg("make tmpfile for certificate or key data failed (error = %d)", errno);
    }
    /* Awkward casts required for MinGW with -O0 only */
    assert_int_equal(write(certfd, unittest_cert, (unsigned int)strlen(unittest_cert)),
                     strlen(unittest_cert));
    assert_int_equal(write(keyfd, unittest_key, (unsigned int)strlen(unittest_key)),
                     strlen(unittest_key));
    close(certfd);
    close(keyfd);
    return 0;
}

static int
cleanup(void **state)
{
    (void)state;
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
    (void)state;
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
    (void)state;

#if !defined(HAVE_OPENSSL_STORE)
    skip();
#else  /* HAVE_OPENSSL_STORE */

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

static void
encrypt_one_packet(struct crypto_options *co, int len)
{
    struct frame frame;
    init_frame_parameters(&frame);

    struct gc_arena gc = gc_new();
    struct buffer encrypt_workspace = alloc_buf_gc(BUF_SIZE(&frame), &gc);
    struct buffer decrypt_workspace = alloc_buf_gc(BUF_SIZE(&frame), &gc);
    struct buffer work = alloc_buf_gc(BUF_SIZE(&frame), &gc);
    struct buffer buf = clear_buf();
    struct buffer src = alloc_buf_gc(frame.buf.payload_size, &gc);
    void *buf_p;

    ASSERT(buf_init(&work, frame.buf.headroom));

    /*
     * Load src with random data.
     */
    ASSERT(buf_init(&src, 0));
    ASSERT(len <= src.capacity);
    src.len = len;
    ASSERT(rand_bytes(BPTR(&src), BLEN(&src)));

    /* copy source to input buf */
    buf = work;
    buf_p = buf_write_alloc(&buf, BLEN(&src));
    ASSERT(buf_p);
    memcpy(buf_p, BPTR(&src), BLEN(&src));

    ASSERT(buf_init(&encrypt_workspace, frame.buf.headroom));
    openvpn_encrypt(&buf, encrypt_workspace, co);

    /* decrypt */
    openvpn_decrypt(&buf, decrypt_workspace, co, &frame, BPTR(&buf));

    /* compare */
    assert_int_equal(buf.len, src.len);
    assert_memory_equal(BPTR(&src), BPTR(&buf), len);

    gc_free(&gc);
}


static void
check_aead_limits(struct crypto_options *co, bool chachapoly)
{
    /* Check that we correctly react when we have a nearing AEAD limits */

    /* manually increase the send counter to be past
     * the GCM usage limit */
    co->key_ctx_bi.encrypt.plaintext_blocks = 0x1ull << 40;


    bool epoch = (co->flags & CO_EPOCH_DATA_KEY_FORMAT);

    int expected_epoch = epoch ? 4 : 0;

    /* Ensure that we are still on the initial key (our init_crypto_options
     * unit test method iterates the initial key to 4) or that it is 0 when
     * epoch is not in use
     */
    assert_int_equal(co->key_ctx_bi.encrypt.epoch, expected_epoch);

    encrypt_one_packet(co, 1000);

    /* either epoch key has been updated or warning is enabled */
    if (epoch && !chachapoly)
    {
        expected_epoch++;
    }

    assert_int_equal(co->key_ctx_bi.encrypt.epoch, expected_epoch);

    if (!epoch)
    {
        /* Check always against the GCM usage limit here to see if that
         * check works */
        assert_true(
            aead_usage_limit_reached((1ull << 36), &co->key_ctx_bi.encrypt, co->packet_id.send.id));
        return;
    }

    /* Move to the end of the epoch data key send PID range, ChachaPoly
     * should now also move to a new epoch data key */
    co->packet_id.send.id = PACKET_ID_EPOCH_MAX;

    encrypt_one_packet(co, 1000);
    encrypt_one_packet(co, 1000);

    expected_epoch++;
    assert_int_equal(co->key_ctx_bi.encrypt.epoch, expected_epoch);
}


static struct crypto_options
init_crypto_options(const char *cipher, const char *auth, bool epoch, struct key2 *statickey)
{
    struct key2 key2 = { .n = 2 };

    if (statickey)
    {
        /* Use chosen static key instead of random key when defined */
        key2 = *statickey;
    }
    else
    {
        ASSERT(rand_bytes(key2.keys[0].cipher, sizeof(key2.keys[0].cipher)));
        ASSERT(rand_bytes(key2.keys[0].hmac, sizeof(key2.keys[0].hmac)));
        ASSERT(rand_bytes(key2.keys[1].cipher, sizeof(key2.keys[1].cipher)));
        ASSERT(rand_bytes(key2.keys[1].hmac, sizeof(key2.keys)[1].hmac));
    }

    struct crypto_options co = { 0 };

    struct key_type kt = create_kt(cipher, auth, "ssl-test");

    if (epoch)
    {
        struct epoch_key e1 = { .epoch = 1, .epoch_key = { 0 } };
        memcpy(e1.epoch_key, key2.keys[0].cipher, sizeof(e1.epoch_key));
        co.flags |= CO_EPOCH_DATA_KEY_FORMAT;
        epoch_init_key_ctx(&co, &kt, &e1, &e1, 5);

        /* Do a little of dancing for the epoch_send_key_iterate to test
         * that this works too */
        epoch_iterate_send_key(&co);
        epoch_iterate_send_key(&co);
        epoch_iterate_send_key(&co);
    }
    else
    {
        init_key_ctx_bi(&co.key_ctx_bi, &key2, KEY_DIRECTION_BIDIRECTIONAL, &kt, "unit-test-ssl");
    }
    packet_id_init(&co.packet_id, 5, 5, "UNITTEST", 0);
    return co;
}

static void
uninit_crypto_options(struct crypto_options *co)
{
    packet_id_free(&co->packet_id);
    free_key_ctx_bi(&co->key_ctx_bi);
    free_epoch_key_ctx(co);
}

/* This adds a few more methods than strictly necessary but this allows
 * us to see which exact test was run from the backtrace of the test
 * when it fails */
static void
run_data_channel_with_cipher_epoch(const char *cipher)
{
    bool ischacha = !strcmp(cipher, "ChaCha20-Poly1305");

    struct crypto_options co = init_crypto_options(cipher, "none", true, NULL);
    do_data_channel_round_trip(&co);
    check_aead_limits(&co, ischacha);
    uninit_crypto_options(&co);
}

static void
run_data_channel_with_cipher(const char *cipher, const char *auth)
{
    bool ischacha = !strcmp(cipher, "ChaCha20-Poly1305");
    struct crypto_options co = init_crypto_options(cipher, auth, false, NULL);
    do_data_channel_round_trip(&co);
    check_aead_limits(&co, ischacha);
    uninit_crypto_options(&co);
}


static void
test_data_channel_roundtrip_aes_128_gcm(void **state)
{
    run_data_channel_with_cipher("AES-128-GCM", "none");
}

static void
test_data_channel_roundtrip_aes_128_gcm_epoch(void **state)
{
    run_data_channel_with_cipher_epoch("AES-128-GCM");
}

static void
test_data_channel_roundtrip_aes_192_gcm(void **state)
{
    run_data_channel_with_cipher("AES-192-GCM", "none");
}

static void
test_data_channel_roundtrip_aes_192_gcm_epoch(void **state)
{
    run_data_channel_with_cipher_epoch("AES-192-GCM");
}

static void
test_data_channel_roundtrip_aes_256_gcm(void **state)
{
    run_data_channel_with_cipher("AES-256-GCM", "none");
}

static void
test_data_channel_roundtrip_aes_256_gcm_epoch(void **state)
{
    run_data_channel_with_cipher_epoch("AES-256-GCM");
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
test_data_channel_roundtrip_chacha20_poly1305_epoch(void **state)
{
    if (!cipher_valid("ChaCha20-Poly1305"))
    {
        skip();
        return;
    }

    run_data_channel_with_cipher_epoch("ChaCha20-Poly1305");
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


static struct key2
create_key(void)
{
    struct key2 key2 = { .n = 2 };

    const uint8_t key[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', '0', '1', '2',
                            '3', '4', '5', '6', '7', 'A', 'B', 'C', 'D', 'E', 'F',
                            'G', 'H', 'j', 'k', 'u', 'c', 'h', 'e', 'n', 'l' };

    static_assert(sizeof(key) == 32, "Size of key should be 32 bytes");

    /* copy the key a few times to ensure to have the size we need for
     * Statickey but XOR it to not repeat it */
    uint8_t keydata[sizeof(key2.keys)];

    for (int i = 0; i < sizeof(key2.keys); i++)
    {
        keydata[i] = (uint8_t)(key[i % sizeof(key)] ^ i);
    }

    ASSERT(memcpy(key2.keys[0].cipher, keydata, sizeof(key2.keys[0].cipher)));
    ASSERT(memcpy(key2.keys[0].hmac, keydata + 64, sizeof(key2.keys[0].hmac)));
    ASSERT(memcpy(key2.keys[1].cipher, keydata + 128, sizeof(key2.keys[1].cipher)));
    ASSERT(memcpy(key2.keys[1].hmac, keydata + 192, sizeof(key2.keys)[1].hmac));

    return key2;
}

static void
test_data_channel_known_vectors_run(bool epoch)
{
    struct key2 key2 = create_key();

    struct crypto_options co = init_crypto_options("AES-256-GCM", "none", epoch, &key2);

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

    now = 0;

    /*
     * Load src with known data.
     */
    ASSERT(buf_init(&src, 0));
    const char *plaintext = "The quick little fox jumps over the bureaucratic hurdles";

    ASSERT(buf_write(&src, plaintext, strlen(plaintext)));

    /* copy source to input buf */
    buf = work;
    buf_p = buf_write_alloc(&buf, BLEN(&src));
    ASSERT(buf_p);
    memcpy(buf_p, BPTR(&src), BLEN(&src));

    /* initialize work buffer with buf.headroom bytes of prepend capacity */
    ASSERT(buf_init(&encrypt_workspace, frame.buf.headroom));

    /* add packet opcode and peer id */
    buf_write_u8(&encrypt_workspace, 7);
    buf_write_u8(&encrypt_workspace, 0);
    buf_write_u8(&encrypt_workspace, 0);
    buf_write_u8(&encrypt_workspace, 23);

    /* encrypt */
    openvpn_encrypt(&buf, encrypt_workspace, &co);

    /* separate buffer in authenticated data and encrypted data */
    uint8_t *ad_start = BPTR(&buf);
    buf_advance(&buf, 4);

    if (epoch)
    {
        uint8_t packetid1[8] = { 0, 0x04, 0, 0, 0, 0, 0, 1 };
        assert_memory_equal(BPTR(&buf), packetid1, 8);
    }
    else
    {
        uint8_t packetid1[4] = { 0, 0, 0, 1 };
        assert_memory_equal(BPTR(&buf), packetid1, 4);
    }

    if (epoch)
    {
        uint8_t *tag_location = BEND(&buf) - OPENVPN_AEAD_TAG_LENGTH;
        const uint8_t exp_tag_epoch[16] = { 0x0f, 0xff, 0xf5, 0x91, 0x3d, 0x39, 0xd7, 0x5b,
                                            0x18, 0x57, 0x3b, 0x57, 0x48, 0x58, 0x9a, 0x7d };

        assert_memory_equal(tag_location, exp_tag_epoch, OPENVPN_AEAD_TAG_LENGTH);
    }
    else
    {
        uint8_t *tag_location = BPTR(&buf) + 4;
        const uint8_t exp_tag_noepoch[16] = { 0x1f, 0xdd, 0x90, 0x8f, 0x0e, 0x9d, 0xc2, 0x5e,
                                              0x79, 0xd8, 0x32, 0x02, 0x0d, 0x58, 0xe7, 0x3f };
        assert_memory_equal(tag_location, exp_tag_noepoch, OPENVPN_AEAD_TAG_LENGTH);
    }

    /* Check some bytes at the beginning of the encrypted part */
    if (epoch)
    {
        const uint8_t bytesat14[6] = { 0x36, 0xaa, 0xb4, 0xd4, 0x9c, 0xe6 };
        assert_memory_equal(BPTR(&buf) + 14, bytesat14, sizeof(bytesat14));
    }
    else
    {
        const uint8_t bytesat30[6] = { 0xa8, 0x2e, 0x6b, 0x17, 0x06, 0xd9 };
        assert_memory_equal(BPTR(&buf) + 30, bytesat30, sizeof(bytesat30));
    }

    /* decrypt */
    openvpn_decrypt(&buf, decrypt_workspace, &co, &frame, ad_start);

    /* compare */
    assert_int_equal(buf.len, strlen(plaintext));
    assert_memory_equal(BPTR(&buf), plaintext, strlen(plaintext));

    uninit_crypto_options(&co);
    gc_free(&gc);
}

static void
test_data_channel_known_vectors_epoch(void **state)
{
    test_data_channel_known_vectors_run(true);
}

static void
test_data_channel_known_vectors_shortpktid(void **state)
{
    test_data_channel_known_vectors_run(false);
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
        cmocka_unit_test(test_data_channel_roundtrip_aes_128_gcm_epoch),
        cmocka_unit_test(test_data_channel_roundtrip_aes_192_gcm),
        cmocka_unit_test(test_data_channel_roundtrip_aes_192_gcm_epoch),
        cmocka_unit_test(test_data_channel_roundtrip_aes_256_gcm),
        cmocka_unit_test(test_data_channel_roundtrip_aes_256_gcm_epoch),
        cmocka_unit_test(test_data_channel_roundtrip_chacha20_poly1305),
        cmocka_unit_test(test_data_channel_roundtrip_chacha20_poly1305_epoch),
        cmocka_unit_test(test_data_channel_roundtrip_aes_128_cbc),
        cmocka_unit_test(test_data_channel_roundtrip_aes_192_cbc),
        cmocka_unit_test(test_data_channel_roundtrip_aes_256_cbc),
        cmocka_unit_test(test_data_channel_roundtrip_bf_cbc),
        cmocka_unit_test(test_data_channel_known_vectors_epoch),
        cmocka_unit_test(test_data_channel_known_vectors_shortpktid)
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
