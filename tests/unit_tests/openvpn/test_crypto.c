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

#include "crypto.h"

#include "mock_msg.h"

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
    const cipher_kt_t *cipher = cipher_kt_get(ciphername);

    /* Empty cipher is fine */
    if (!cipher)
    {
        return;
    }

    const char *kt_name = cipher_kt_name(cipher);

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
        upper[i] = toupper(ciphername[i]);
        lower[i] = tolower(ciphername[i]);
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

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(crypto_pem_encode_decode_loopback),
        cmocka_unit_test(crypto_translate_cipher_names),
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
