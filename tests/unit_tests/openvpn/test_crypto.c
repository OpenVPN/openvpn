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

#include "crypto.h"
#include "crypto_epoch.h"
#include "options.h"
#include "ssl_backend.h"

#include "mss.h"
#include "test_common.h"


#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#endif

static const char testtext[] = "Dummy text to test PEM encoding";

static void
crypto_pem_encode_decode_loopback(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer src_buf;
    buf_set_read(&src_buf, (void *)testtext, sizeof(testtext));

    uint8_t dec[sizeof(testtext)];
    struct buffer dec_buf;
    buf_set_write(&dec_buf, dec, sizeof(dec));

    struct buffer pem_buf;

    assert_true(crypto_pem_encode("TESTKEYNAME", &pem_buf, &src_buf, &gc));
    assert_true(BLEN(&src_buf) < BLEN(&pem_buf));

    /* Wrong key name */
    assert_false(crypto_pem_decode("WRONGNAME", &dec_buf, &pem_buf));

    assert_true(crypto_pem_decode("TESTKEYNAME", &dec_buf, &pem_buf));
    assert_int_equal(BLEN(&src_buf), BLEN(&dec_buf));
    assert_memory_equal(BPTR(&src_buf), BPTR(&dec_buf), BLEN(&src_buf));

    gc_free(&gc);
}

static void
test_translate_cipher(const char *ciphername, const char *openvpn_name)
{
    bool cipher = cipher_valid(ciphername);

    /* Empty cipher is fine */
    if (!cipher)
    {
        return;
    }

    const char *kt_name = cipher_kt_name(ciphername);

    assert_string_equal(kt_name, openvpn_name);
}

static void
test_cipher_names(const char *ciphername, const char *openvpn_name)
{
    struct gc_arena gc = gc_new();
    /* Go through some variants, if the cipher library accepts these, they
     * should be normalised to the openvpn name */
    char *upper = string_alloc(ciphername, &gc);
    char *lower = string_alloc(ciphername, &gc);
    char *random_case = string_alloc(ciphername, &gc);

    for (int i = 0; i < strlen(ciphername); i++)
    {
        upper[i] = (char)toupper((unsigned char)ciphername[i]);
        lower[i] = (char)tolower((unsigned char)ciphername[i]);
        if (rand() & 0x1)
        {
            random_case[i] = upper[i];
        }
        else
        {
            random_case[i] = lower[i];
        }
    }

    if (!openvpn_name)
    {
        openvpn_name = upper;
    }

    test_translate_cipher(upper, openvpn_name);
    test_translate_cipher(lower, openvpn_name);
    test_translate_cipher(random_case, openvpn_name);
    test_translate_cipher(ciphername, openvpn_name);


    gc_free(&gc);
}

static void
crypto_translate_cipher_names(void **state)
{
    /* Test that a number of ciphers to see that they turn out correctly */
    test_cipher_names("BF-CBC", NULL);
    test_cipher_names("BLOWFISH-CBC", "BF-CBC");
    test_cipher_names("Chacha20-Poly1305", NULL);
    test_cipher_names("AES-128-GCM", NULL);
    test_cipher_names("AES-128-CBC", NULL);
    test_cipher_names("CAMELLIA-128-CFB128", "CAMELLIA-128-CFB");
    test_cipher_names("id-aes256-GCM", "AES-256-GCM");
}


static const char *ipsumlorem = "Lorem ipsum dolor sit amet, consectetur "
                                "adipisici elit, sed eiusmod tempor incidunt "
                                "ut labore et dolore magna aliqua.";

static void
crypto_test_tls_prf(void **state)
{
    const char *seedstr = "Quis aute iure reprehenderit in voluptate "
                          "velit esse cillum dolore";
    const unsigned char *seed = (const unsigned char *)seedstr;
    const size_t seed_len = strlen(seedstr);


    const unsigned char *secret = (const unsigned char *) ipsumlorem;
    size_t secret_len = strlen((const char *)secret);


    uint8_t out[32];
    bool ret = ssl_tls1_PRF(seed, (int)seed_len, secret, (int)secret_len, out, sizeof(out));

#if defined(LIBRESSL_VERSION_NUMBER) || defined(ENABLE_CRYPTO_WOLFSSL)
    /* No TLS1 PRF support in these libraries */
    assert_false(ret);
#else
    assert_true(ret);
    uint8_t good_prf[32] = {0xd9, 0x8c, 0x85, 0x18, 0xc8, 0x5e, 0x94, 0x69,
                            0x27, 0x91, 0x6a, 0xcf, 0xc2, 0xd5, 0x92, 0xfb,
                            0xb1, 0x56, 0x7e, 0x4b, 0x4b, 0x14, 0x59, 0xe6,
                            0xa9, 0x04, 0xac, 0x2d, 0xda, 0xb7, 0x2d, 0x67};
    assert_memory_equal(good_prf, out, sizeof(out));
#endif
}

static uint8_t testkey[20] = {0x0b, 0x00};
static uint8_t goodhash[20] = {0x58, 0xea, 0x5a, 0xf0, 0x42, 0x94, 0xe9, 0x17,
                               0xed, 0x84, 0xb9, 0xf0, 0x83, 0x30, 0x23, 0xae,
                               0x8b, 0xa7, 0x7e, 0xb8};

static void
crypto_test_hmac(void **state)
{
    hmac_ctx_t *hmac = hmac_ctx_new();

    assert_int_equal(md_kt_size("SHA1"), 20);

    uint8_t key[20];
    memcpy(key, testkey, sizeof(key));

    hmac_ctx_init(hmac, key, "SHA1");
    hmac_ctx_update(hmac, (const uint8_t *)ipsumlorem, (int) strlen(ipsumlorem));
    hmac_ctx_update(hmac, (const uint8_t *)ipsumlorem, (int) strlen(ipsumlorem));

    uint8_t hash[20];
    hmac_ctx_final(hmac, hash);

    assert_memory_equal(hash, goodhash, sizeof(hash));
    memset(hash, 0x00, sizeof(hash));

    /* try again */
    hmac_ctx_reset(hmac);
    hmac_ctx_update(hmac, (const uint8_t *)ipsumlorem, (int) strlen(ipsumlorem));
    hmac_ctx_update(hmac, (const uint8_t *)ipsumlorem, (int) strlen(ipsumlorem));
    hmac_ctx_final(hmac, hash);

    assert_memory_equal(hash, goodhash, sizeof(hash));

    /* Fill our key with random data to ensure it is not used by hmac anymore */
    memset(key, 0x55, sizeof(key));

    hmac_ctx_reset(hmac);
    hmac_ctx_update(hmac, (const uint8_t *)ipsumlorem, (int) strlen(ipsumlorem));
    hmac_ctx_update(hmac, (const uint8_t *)ipsumlorem, (int) strlen(ipsumlorem));
    hmac_ctx_final(hmac, hash);

    assert_memory_equal(hash, goodhash, sizeof(hash));
    hmac_ctx_cleanup(hmac);
    hmac_ctx_free(hmac);
}

/* This test is in test_crypto as it calls into the functions that calculate
 * the crypto overhead */
static void
test_occ_mtu_calculation(void **state)
{
    struct gc_arena gc = gc_new();

    struct frame f = { 0 };
    struct options o = { 0 };
    size_t linkmtu;

    /* common defaults */
    o.ce.tun_mtu = 1400;
    o.ce.proto = PROTO_UDP;

    /* No crypto at all */
    o.ciphername = "none";
    o.authname = "none";
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1400);

    /* Static key OCC examples */
    o.shared_secret_file = "not null";

    /* secret, auth none, cipher none */
    o.ciphername = "none";
    o.authname = "none";
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1408);

    /* secret, cipher AES-128-CBC, auth none */
    o.ciphername = "AES-128-CBC";
    o.authname = "none";
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1440);

    /* secret, cipher none, auth SHA256 */
    o.ciphername = "none";
    o.authname = "SHA256";
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1440);

    /* secret, cipher BF-CBC, auth SHA1 */
    o.ciphername = "BF-CBC";
    o.authname = "SHA1";
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1444);

    /* secret, cipher BF-CBC, auth SHA1, tcp-client */
    o.ce.proto = PROTO_TCP_CLIENT;
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1446);

    o.ce.proto = PROTO_UDP;

#if defined(USE_COMP)
    o.comp.alg = COMP_ALG_LZO;

    /* secret, comp-lzo yes, cipher BF-CBC, auth SHA1 */
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1445);

#if defined(ENABLE_FRAGMENT)
    /* secret, comp-lzo yes, cipher BF-CBC, auth SHA1, fragment 1200 */
    o.ce.fragment = 1200;
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1449);
    o.ce.fragment = 0;
#endif

    o.comp.alg = COMP_ALG_UNDEF;
#endif

    /* TLS mode */
    o.shared_secret_file = NULL;
    o.tls_client = true;
    o.pull = true;

    /* tls client, cipher AES-128-CBC, auth SHA1, tls-auth */
    o.authname = "SHA1";
    o.ciphername = "AES-128-CBC";
    o.tls_auth_file = "dummy";

    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1457);

    /* tls client, cipher AES-128-CBC, auth SHA1 */
    o.tls_auth_file = NULL;

    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1457);

    /* tls client, cipher none, auth none */
    o.authname = "none";
    o.ciphername = "none";

    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1405);

    /* tls client, auth SHA1, cipher AES-256-GCM */
    o.authname = "SHA1";
    o.ciphername = "AES-256-GCM";
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1449);


#if defined(USE_COMP) && defined(ENABLE_FRAGMENT)
    o.comp.alg = COMP_ALG_LZO;

    /* tls client, auth SHA1, cipher AES-256-GCM, fragment, comp-lzo yes */
    o.ce.fragment = 1200;
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1454);

    /* tls client, auth SHA1, cipher AES-256-GCM, fragment, comp-lzo yes, socks */
    o.ce.socks_proxy_server = "socks.example.com";
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1464);
#endif

    gc_free(&gc);
}

static void
test_mssfix_mtu_calculation(void **state)
{
    struct gc_arena gc = gc_new();

    struct frame f = { 0 };
    struct options o = { 0 };

    /* common defaults */
    o.ce.tun_mtu = 1400;
    o.ce.mssfix = 1000;
    o.ce.proto = PROTO_UDP;

    /* No crypto at all */
    o.ciphername = "none";
    o.authname = "none";
    struct key_type kt;
    init_key_type(&kt, o.ciphername, o.authname, false, false);

    /* No encryption, just packet id (8) + TCP payload(20) + IP payload(20) */
    frame_calculate_dynamic(&f, &kt, &o, NULL);
    assert_int_equal(f.mss_fix, 952);

    /* Static key OCC examples */
    o.shared_secret_file = "not null";

    /* secret, auth none, cipher none */
    o.ciphername = "none";
    o.authname = "none";
    init_key_type(&kt, o.ciphername, o.authname, false, false);
    frame_calculate_dynamic(&f, &kt, &o, NULL);
    assert_int_equal(f.mss_fix, 952);

    /* secret, cipher AES-128-CBC, auth none */
    o.ciphername = "AES-128-CBC";
    o.authname = "none";
    init_key_type(&kt, o.ciphername, o.authname, false, false);

    for (int i = 990; i <= 1010; i++)
    {
        /* 992 - 1008 should end up with the same mssfix value all they
         * all result in the same CBC block size/padding and <= 991 and >=1008
         * should be one block less and more respectively */
        o.ce.mssfix = i;
        frame_calculate_dynamic(&f, &kt, &o, NULL);
        if (i <= 991)
        {
            assert_int_equal(f.mss_fix, 911);
        }
        else if (i >= 1008)
        {
            assert_int_equal(f.mss_fix, 943);
        }
        else
        {
            assert_int_equal(f.mss_fix, 927);
        }
    }
#ifdef USE_COMP
    o.comp.alg = COMP_ALG_LZO;

    /* Same but with compression added. Compression adds one byte extra to the
     * payload so the payload should be reduced by compared to the no
     * compression calculation before */
    for (int i = 990; i <= 1010; i++)
    {
        /* 992 - 1008 should end up with the same mssfix value all they
         * all result in the same CBC block size/padding and <= 991 and >=1008
         * should be one block less and more respectively */
        o.ce.mssfix = i;
        frame_calculate_dynamic(&f, &kt, &o, NULL);
        if (i <= 991)
        {
            assert_int_equal(f.mss_fix, 910);
        }
        else if (i >= 1008)
        {
            assert_int_equal(f.mss_fix, 942);
        }
        else
        {
            assert_int_equal(f.mss_fix, 926);
        }
    }
    o.comp.alg = COMP_ALG_UNDEF;
#endif /* ifdef USE_COMP */

    /* tls client, auth SHA1, cipher AES-256-GCM */
    o.authname = "SHA1";
    o.ciphername = "AES-256-GCM";
    o.tls_client = true;
    o.peer_id = 77;
    o.use_peer_id = true;
    init_key_type(&kt, o.ciphername, o.authname, true, false);

    for (int i = 900; i <= 1200; i++)
    {
        /* For stream ciphers, the value should not be influenced by block
         * sizes or similar but always have the same difference */
        o.ce.mssfix = i;
        frame_calculate_dynamic(&f, &kt, &o, NULL);

        /* 4 byte opcode/peerid, 4 byte pkt ID, 16 byte tag, 40 TCP+IP */
        assert_int_equal(f.mss_fix, i - 4 - 4 - 16 - 40);
    }

    gc_free(&gc);
}

void
crypto_test_aead_limits(void **state)
{
    /* if ChaCha20-Poly1305 is not supported by the crypto library or in the
     * current mode (FIPS), this will still return -1 */
    assert_int_equal(cipher_get_aead_limits("CHACHA20-POLY1305"), 0);

    int64_t aeslimit = cipher_get_aead_limits("AES-128-GCM");

    assert_int_equal(aeslimit, (1ull << 36) - 1);

    /* Check if this matches our exception for 1600 size packets assuming
     * AEAD_LIMIT_BLOCKSIZE (128 bits/ 16 bytes). Gives us 100 blocks
     * + 1 for the packet */
    int64_t L = 101;
    /* 2 ^ 29.34, using the result here to avoid linking to libm */
    assert_int_equal(aeslimit / L, 680390858);

    /* and for 9000, 2^26.86 */
    L = 563;
    assert_int_equal(aeslimit / L, 122059461);
}

void
crypto_test_hkdf_expand_testa1(void **state)
{
    /* RFC 5889 A.1 Test Case 1 */
    uint8_t prk[32] =
    {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
     0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
     0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
     0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};

    uint8_t info[10] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
                        0xf6, 0xf7, 0xf8, 0xf9};

    uint8_t okm[42] =
    {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
     0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
     0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
     0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
     0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
     0x58, 0x65};

    uint8_t out[42];
    ovpn_hkdf_expand(prk, info, sizeof(info), out, sizeof(out));

    assert_memory_equal(out, okm, sizeof(out));
}

void
crypto_test_hkdf_expand_testa2(void **state)
{
    /* RFC 5889 A.2 Test Case 2 */
    uint8_t prk[32] =
    {0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a,
     0x06, 0x10, 0x4c, 0x9c, 0xeb, 0x35, 0xb4, 0x5c,
     0xef, 0x76, 0x00, 0x14, 0x90, 0x46, 0x71, 0x01,
     0x4a, 0x19, 0x3f, 0x40, 0xc1, 0x5f, 0xc2, 0x44};

    uint8_t info[80] =
    {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
     0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
     0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
     0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
     0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
     0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
     0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
     0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
     0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
     0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

    const int L = 82;
    uint8_t okm[82] =
    {0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1,
     0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
     0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
     0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
     0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72,
     0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
     0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
     0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
     0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
     0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
     0x1d, 0x87};

    uint8_t out[82] = {0xaa};
    ovpn_hkdf_expand(prk, info, sizeof(info), out, L);

    assert_memory_equal(out, okm, L);
}

void
crypto_test_hkdf_expand_testa3(void **state)
{
    /* RFC 5889 A.3 Test Case 3 */
    uint8_t prk[32] =
    {0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16,
     0x7f, 0x33, 0xa9, 0x1d, 0x6f, 0x64, 0x8b, 0xdf,
     0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb, 0x63, 0x77,
     0xac, 0x43, 0x4c, 0x1c, 0x29, 0x3c, 0xcb, 0x04};

    uint8_t info[] = {};

    int L = 42;
    uint8_t okm[42] =
    {0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
     0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
     0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
     0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
     0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
     0x96, 0xc8};

    uint8_t out[42];
    ovpn_hkdf_expand(prk, info, 0, out, L);

    assert_memory_equal(out, okm, L);
}

void
crypto_test_hkdf_expand_test_ovpn(void **state)
{
    /* tests the HDKF with a label/okm that OpenVPN itself uses in OpenSSL 3
     * HDKF unit test*/

    uint8_t prk[32] =
    {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
     0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
     0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
     0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};

    uint8_t info[18] =
    {0x00, 0x1b, 0x0e, 0x6f, 0x76, 0x70, 0x6e, 0x20,
     0x75, 0x6e, 0x69, 0x74, 0x20, 0x74, 0x65, 0x73,
     0x74, 0x00};

    int L = 27;
    uint8_t okm[27] =
    {0x87, 0x5a, 0x8e, 0xec, 0x18, 0x55, 0x63, 0x80,
     0xb8, 0xd9, 0x33, 0xed, 0x32, 0x3c, 0x2d, 0xf8,
     0xe8, 0xec, 0xcf, 0x49, 0x72, 0xe6, 0x83, 0xf0,
     0x6a, 0x83, 0xac };

    uint8_t out[27];
    ovpn_hkdf_expand(prk, info, sizeof(info), out, L);

    assert_memory_equal(out, okm, L);
}

void
crypto_test_ovpn_label_expand(void **state)
{
    uint8_t secret[32] =
    {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
     0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
     0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
     0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};

    const uint8_t *label = (const uint8_t *) ("unit test");
    uint8_t out[16];
    ovpn_expand_label(secret, sizeof(secret), label, 9, NULL, 0, out, sizeof(out));

    uint8_t out_expected[16] =
    {0x18, 0x5e, 0xaa, 0x1c, 0x7f, 0x22, 0x8a, 0xb8,
     0xeb, 0x29, 0x77, 0x32, 0x14, 0xd9, 0x20, 0x46};

    assert_memory_equal(out, out_expected, 16);
}

#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
/* We have OpenSSL 3.0+, we test if their implementation matches our
 * implementation. We currently do not use this code from the crypto library
 * in the main code yet as we don't want to repeat the mess that the current
 * openvpn_PRF ifdef maze */

bool
ossl_expand_label(const uint8_t *secret, size_t secret_len,
                  const uint8_t *label, size_t label_len,
                  const uint8_t *context, size_t context_len,
                  uint8_t *out, uint16_t out_len)
{
    OSSL_LIB_CTX *libctx = NULL;
    const char *properties = NULL;

    const uint8_t *label_prefix = (const uint8_t *) ("ovpn ");
    const size_t label_prefix_len = 5;

    EVP_KDF *kdf = EVP_KDF_fetch(libctx, OSSL_KDF_NAME_TLS1_3_KDF, properties);
    assert_non_null(kdf);

    const char *mdname = "SHA-256";

    size_t hashlen = SHA256_DIGEST_LENGTH;

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    assert_non_null(kctx);

    OSSL_PARAM params[7];
    OSSL_PARAM *p = params;

    int mode = EVP_PKEY_HKDEF_MODE_EXPAND_ONLY;

    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            (char *) mdname, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                             (unsigned char *) secret, hashlen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PREFIX,
                                             (unsigned char *) label_prefix,
                                             label_prefix_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL,
                                             (unsigned char *) label, label_len);

    *p++ = OSSL_PARAM_construct_end();

    int ret = EVP_KDF_derive(kctx, out, out_len, params);
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);

    assert_int_equal(ret, 1);
    return true;
}

void
crypto_test_ovpn_expand_openssl3(void **state)
{
    uint8_t secret[32] =
    {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
     0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
     0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
     0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};

    const uint8_t *label = (const uint8_t *) ("unit test");
    const size_t labellen = 9;
    uint8_t out[27];

    ossl_expand_label(secret, sizeof(secret), label, labellen, NULL, 0, out, sizeof(out));

    /* Do the same derivation with our own function */
    uint8_t out_ovpn[27];

    ovpn_expand_label(secret, sizeof(secret), label, 9, NULL, 0, out_ovpn, sizeof(out_ovpn));
    assert_memory_equal(out_ovpn, out, sizeof(out_ovpn));
}

#else  /* if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L */
void
crypto_test_ovpn_expand_openssl3(void **state)
{
    skip();
}
#endif /* if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L */

struct epoch_test_state
{
    struct key_type kt;
    struct gc_arena gc;
    struct crypto_options co;
};

static int
crypto_test_epoch_setup(void **state)
{
    int *num_future_keys = (int *)*state;
    struct epoch_test_state *data = calloc(1, sizeof(struct epoch_test_state));

    data->gc = gc_new();

    init_key_type(&data->kt, "AES-128-GCM", "none", true, false);

    /* have an epoch key that uses 0x23 for the key for all bytes */
    struct epoch_key epoch1send = { .epoch = 1, .epoch_key = {0x23} };
    struct epoch_key epoch1recv = { .epoch = 1, .epoch_key = {0x27} };

    epoch_init_key_ctx(&data->co, &data->kt, &epoch1send,
                       &epoch1recv, *num_future_keys);

    *state = data;
    return 0;
}

static int
crypto_test_epoch_teardown(void **state)
{
    struct epoch_test_state *data = *state;
    free_epoch_key_ctx(&data->co);
    free_key_ctx_bi(&data->co.key_ctx_bi);
    gc_free(&data->gc);
    free(*state);
    return 0;
}

void
crypto_test_epoch_key_generation(void **state)
{
    struct epoch_test_state *data = *state;
    struct crypto_options *co = &data->co;

    /* check the keys look like expect */
    assert_int_equal(co->epoch_data_keys_future[0].epoch, 2);
    assert_int_equal(co->epoch_data_keys_future[15].epoch, 17);
    assert_int_equal(co->epoch_key_send.epoch, 1);
    assert_int_equal(co->epoch_key_recv.epoch, 17);

    /* Now replace the recv key with the 6th future key (epoch = 8) */
    free_key_ctx(&co->key_ctx_bi.decrypt);
    assert_int_equal(co->epoch_data_keys_future[6].epoch, 8);
    co->key_ctx_bi.decrypt = co->epoch_data_keys_future[6];
    CLEAR(co->epoch_data_keys_future[6]);

    epoch_generate_future_receive_keys(co);
    assert_int_equal(co->epoch_data_keys_future[0].epoch, 9);
    assert_int_equal(co->epoch_data_keys_future[15].epoch, 24);
}


void
crypto_test_epoch_key_rotation(void **state)
{
    struct epoch_test_state *data = *state;
    struct crypto_options *co = &data->co;

    /* should replace send + key recv */
    epoch_replace_update_recv_key(co, 9);

    assert_int_equal(co->key_ctx_bi.decrypt.epoch, 9);
    assert_int_equal(co->key_ctx_bi.encrypt.epoch, 9);
    assert_int_equal(co->epoch_key_send.epoch, 9);
    assert_int_equal(co->epoch_retiring_data_receive_key.epoch, 1);

    /* Iterate the data send key four times to get it to 13 */
    for (int i = 0; i < 4; i++)
    {
        epoch_iterate_send_key(co);
    }
    assert_int_equal(co->key_ctx_bi.encrypt.epoch, 13);

    epoch_replace_update_recv_key(co, 10);
    assert_int_equal(co->key_ctx_bi.decrypt.epoch, 10);
    assert_int_equal(co->key_ctx_bi.encrypt.epoch, 13);
    assert_int_equal(co->epoch_key_send.epoch, 13);
    assert_int_equal(co->epoch_retiring_data_receive_key.epoch, 9);

    epoch_replace_update_recv_key(co, 12);
    assert_int_equal(co->key_ctx_bi.decrypt.epoch, 12);
    assert_int_equal(co->key_ctx_bi.encrypt.epoch, 13);
    assert_int_equal(co->epoch_key_send.epoch, 13);
    assert_int_equal(co->epoch_retiring_data_receive_key.epoch, 10);

    epoch_iterate_send_key(co);
    assert_int_equal(co->key_ctx_bi.encrypt.epoch, 14);
}

void
crypto_test_epoch_key_receive_lookup(void **state)
{
    struct epoch_test_state *data = *state;
    struct crypto_options *co = &data->co;

    /* lookup some wacky things that should fail */
    assert_null(epoch_lookup_decrypt_key(co, 2000));
    assert_null(epoch_lookup_decrypt_key(co, -1));
    assert_null(epoch_lookup_decrypt_key(co, 0xefff));

    /* Lookup the edges of the current window */
    assert_null(epoch_lookup_decrypt_key(co, 0));
    assert_int_equal(co->epoch_retiring_data_receive_key.epoch, 0);
    assert_int_equal(epoch_lookup_decrypt_key(co, 1)->epoch, 1);
    assert_int_equal(epoch_lookup_decrypt_key(co, 2)->epoch, 2);
    assert_int_equal(epoch_lookup_decrypt_key(co, 13)->epoch, 13);
    assert_int_equal(epoch_lookup_decrypt_key(co, 14)->epoch, 14);
    assert_null(epoch_lookup_decrypt_key(co, 15));

    /* Should move 1 to retiring key but leave 2-6 undefined, 7 as
     * active and 8-20 as future keys*/
    epoch_replace_update_recv_key(co, 7);

    assert_null(epoch_lookup_decrypt_key(co, 0));
    assert_int_equal(epoch_lookup_decrypt_key(co, 1)->epoch, 1);
    assert_ptr_equal(epoch_lookup_decrypt_key(co, 1), &co->epoch_retiring_data_receive_key);

    assert_null(epoch_lookup_decrypt_key(co, 2));
    assert_null(epoch_lookup_decrypt_key(co, 3));
    assert_null(epoch_lookup_decrypt_key(co, 4));
    assert_null(epoch_lookup_decrypt_key(co, 5));
    assert_null(epoch_lookup_decrypt_key(co, 6));
    assert_int_equal(epoch_lookup_decrypt_key(co, 7)->epoch, 7);
    assert_int_equal(epoch_lookup_decrypt_key(co, 8)->epoch, 8);
    assert_int_equal(epoch_lookup_decrypt_key(co, 20)->epoch, 20);
    assert_null(epoch_lookup_decrypt_key(co, 21));
    assert_null(epoch_lookup_decrypt_key(co, 22));


    /* Should move 7 to retiring key and have 8 as active key and
     * 9-21 as future keys */
    epoch_replace_update_recv_key(co, 8);
    assert_null(epoch_lookup_decrypt_key(co, 0));
    assert_null(epoch_lookup_decrypt_key(co, 1));
    assert_null(epoch_lookup_decrypt_key(co, 2));
    assert_null(epoch_lookup_decrypt_key(co, 3));
    assert_null(epoch_lookup_decrypt_key(co, 4));
    assert_null(epoch_lookup_decrypt_key(co, 5));
    assert_null(epoch_lookup_decrypt_key(co, 6));
    assert_int_equal(epoch_lookup_decrypt_key(co, 7)->epoch, 7);
    assert_ptr_equal(epoch_lookup_decrypt_key(co, 7), &co->epoch_retiring_data_receive_key);
    assert_int_equal(epoch_lookup_decrypt_key(co, 8)->epoch, 8);
    assert_int_equal(epoch_lookup_decrypt_key(co, 20)->epoch, 20);
    assert_int_equal(epoch_lookup_decrypt_key(co, 21)->epoch, 21);
    assert_null(epoch_lookup_decrypt_key(co, 22));
    assert_null(epoch_lookup_decrypt_key(co, 23));
}

void
crypto_test_epoch_key_overflow(void **state)
{
    struct epoch_test_state *data = *state;
    struct crypto_options *co = &data->co;

    /* Modify the receive epoch and keys to have a very high epoch to test
     * the end of array. Iterating through all 65k keys takes a 2-3s, so we
     * avoid this for the unit test */
    co->key_ctx_bi.decrypt.epoch = 65500;
    co->key_ctx_bi.encrypt.epoch = 65500;

    co->epoch_key_send.epoch = 65500;
    co->epoch_key_recv.epoch = 65500 + co->epoch_data_keys_future_count;

    for (uint16_t i = 0; i < co->epoch_data_keys_future_count; i++)
    {
        co->epoch_data_keys_future[i].epoch = 65501 + i;
    }

    /* Move the last few keys until we are close to the limit */
    while (co->key_ctx_bi.decrypt.epoch < (UINT16_MAX - 40))
    {
        epoch_replace_update_recv_key(co, co->key_ctx_bi.decrypt.epoch + 10);
    }

    /* Looking up this key should still work as it will not break the limit
     * when generating keys */
    assert_int_equal(epoch_lookup_decrypt_key(co, UINT16_MAX - 34)->epoch, UINT16_MAX - 34);
    assert_int_equal(epoch_lookup_decrypt_key(co, UINT16_MAX - 33)->epoch, UINT16_MAX - 33);

    /* This key is no longer eligible for decrypting as the 32 future keys
     * would be larger than uint16_t maximum */
    assert_int_equal(co->epoch_data_keys_future_count, 32);
    assert_null(epoch_lookup_decrypt_key(co, UINT16_MAX - co->epoch_data_keys_future_count));
    assert_null(epoch_lookup_decrypt_key(co, UINT16_MAX));

    /* Check that moving to the last possible epoch works */
    epoch_replace_update_recv_key(co, UINT16_MAX - 33);
    assert_int_equal(epoch_lookup_decrypt_key(co, UINT16_MAX - 33)->epoch, UINT16_MAX - 33);
    assert_null(epoch_lookup_decrypt_key(co, UINT16_MAX - 32));
    assert_null(epoch_lookup_decrypt_key(co, UINT16_MAX));
}

void
epoch_test_derive_data_key(void **state)
{
    struct epoch_key e17 = { .epoch = 17, .epoch_key = { 19, 12 }};
    struct key_type kt = { 0 };
    struct key_parameters key_parameters = { 0 };
    init_key_type(&kt, "AES-192-GCM", "none", true, false);


    epoch_data_key_derive(&key_parameters, &e17, &kt);

    assert_int_equal(key_parameters.cipher_size, 24);
    assert_int_equal(key_parameters.hmac_size, 12);

    uint8_t exp_cipherkey[24] =
    {0xed, 0x85, 0x33, 0xdb, 0x1c, 0x28, 0xac, 0xe4,
     0x18, 0xe9, 0x00, 0x6a, 0xb2, 0x9c, 0x17, 0x41,
     0x7d, 0x60, 0xeb, 0xe6, 0xcd, 0x90, 0xbf, 0x0a};

    uint8_t exp_impl_iv[12] =
    {0x86, 0x89, 0x0a, 0xab, 0xf0, 0x32, 0xcb, 0x59, 0xf4, 0xcf, 0xa3, 0x4e};

    assert_memory_equal(key_parameters.cipher, exp_cipherkey, sizeof(exp_cipherkey));
    assert_memory_equal(key_parameters.hmac, exp_impl_iv, sizeof(exp_impl_iv));
}

int
main(void)
{
    int prestate_num13 = 13;
    int prestate_num16 = 16;
    int prestate_num32 = 32;

    openvpn_unit_test_setup();
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(crypto_pem_encode_decode_loopback),
        cmocka_unit_test(crypto_translate_cipher_names),
        cmocka_unit_test(crypto_test_tls_prf),
        cmocka_unit_test(crypto_test_hmac),
        cmocka_unit_test(test_occ_mtu_calculation),
        cmocka_unit_test(test_mssfix_mtu_calculation),
        cmocka_unit_test(crypto_test_aead_limits),
        cmocka_unit_test(crypto_test_hkdf_expand_testa1),
        cmocka_unit_test(crypto_test_hkdf_expand_testa2),
        cmocka_unit_test(crypto_test_hkdf_expand_testa3),
        cmocka_unit_test(crypto_test_hkdf_expand_test_ovpn),
        cmocka_unit_test(crypto_test_ovpn_label_expand),
        cmocka_unit_test(crypto_test_ovpn_expand_openssl3),
        cmocka_unit_test_prestate_setup_teardown(crypto_test_epoch_key_generation,
                                                 crypto_test_epoch_setup,
                                                 crypto_test_epoch_teardown,
                                                 &prestate_num16),
        cmocka_unit_test_prestate_setup_teardown(crypto_test_epoch_key_rotation,
                                                 crypto_test_epoch_setup,
                                                 crypto_test_epoch_teardown,
                                                 &prestate_num13),
        cmocka_unit_test_prestate_setup_teardown(crypto_test_epoch_key_receive_lookup,
                                                 crypto_test_epoch_setup,
                                                 crypto_test_epoch_teardown,
                                                 &prestate_num13),
        cmocka_unit_test_prestate_setup_teardown(crypto_test_epoch_key_overflow,
                                                 crypto_test_epoch_setup,
                                                 crypto_test_epoch_teardown,
                                                 &prestate_num32),
        cmocka_unit_test(epoch_test_derive_data_key)
    };

#if defined(ENABLE_CRYPTO_OPENSSL)
    OpenSSL_add_all_algorithms();
#endif

    int ret = cmocka_run_group_tests_name("crypto tests", tests, NULL, NULL);

#if defined(ENABLE_CRYPTO_OPENSSL)
    EVP_cleanup();
#endif

    return ret;
}
