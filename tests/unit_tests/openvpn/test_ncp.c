/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2019-2025 Arne Schwabe <arne@rfc2549.org>
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

#include "ssl_ncp.c"
#include "test_common.h"

/* Defines for use in the tests and the mock parse_line() */

const char *bf_chacha = "BF-CBC:CHACHA20-POLY1305";
const char *aes_chacha = "AES-128-CBC:CHACHA20-POLY1305";
const char *aes_ciphers = "AES-256-GCM:AES-128-GCM";


/* Define this function here as dummy since including the ssl_*.c files
 * leads to having to include even more unrelated code */
bool
key_state_export_keying_material(struct tls_session *session,
                                 const char *label, size_t label_size,
                                 void *ekm, size_t ekm_size)
{
    ASSERT(0);
}


/* Define a dummy dco cipher option to avoid linking against all the DCO
 * units */
#if defined(ENABLE_DCO)
const char *
dco_get_supported_ciphers(void)
{
    return "AES-192-GCM:AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305";
}
#endif

static void
test_check_ncp_ciphers_list(void **state)
{
    struct gc_arena gc = gc_new();
    bool have_chacha = cipher_valid("CHACHA20-POLY1305");
    bool have_blowfish = cipher_valid("BF-CBC");

    assert_string_equal(mutate_ncp_cipher_list("none", &gc), "none");
    assert_string_equal(mutate_ncp_cipher_list("AES-256-GCM:none", &gc),
                        "AES-256-GCM:none");

    assert_string_equal(mutate_ncp_cipher_list(aes_ciphers, &gc), aes_ciphers);

    if (have_chacha)
    {
        assert_string_equal(mutate_ncp_cipher_list(aes_chacha, &gc), aes_chacha);
    }

    if (have_chacha && have_blowfish)
    {
        assert_string_equal(mutate_ncp_cipher_list(bf_chacha, &gc), bf_chacha);
        assert_string_equal(mutate_ncp_cipher_list("BF-CBC:CHACHA20-POLY1305", &gc),
                            bf_chacha);
    }
    else
    {
        assert_ptr_equal(mutate_ncp_cipher_list(bf_chacha, &gc), NULL);
    }

    /* Check that optional ciphers work */
    assert_string_equal(mutate_ncp_cipher_list("AES-256-GCM:?vollbit:AES-128-GCM", &gc),
                        aes_ciphers);

    /* Check that optional ciphers work */
    assert_string_equal(mutate_ncp_cipher_list("?AES-256-GCM:?AES-128-GCM", &gc),
                        aes_ciphers);

    /* All unsupported should still yield an empty list */
    assert_ptr_equal(mutate_ncp_cipher_list("?kugelfisch:?grasshopper", &gc), NULL);

    /* If the last is optional, previous invalid ciphers should be ignored */
    assert_ptr_equal(mutate_ncp_cipher_list("Vollbit:Littlebit:AES-256-CBC:BF-CBC:?nixbit", &gc), NULL);

    /* We do not support CCM ciphers */
    assert_ptr_equal(mutate_ncp_cipher_list("AES-256-GCM:AES-128-CCM", &gc), NULL);

    assert_string_equal(mutate_ncp_cipher_list("AES-256-GCM:?AES-128-CCM:AES-128-GCM", &gc),
                        aes_ciphers);

    /* For testing that with OpenSSL 1.1.0+ that also accepts ciphers in
     * a different spelling the normalised cipher output is the same */
    bool have_chacha_mixed_case = cipher_valid("ChaCha20-Poly1305");
    if (have_chacha_mixed_case)
    {
        assert_string_equal(mutate_ncp_cipher_list("AES-128-CBC:ChaCha20-Poly1305", &gc),
                            aes_chacha);
    }

    assert_ptr_equal(mutate_ncp_cipher_list("vollbit", &gc), NULL);
    assert_ptr_equal(mutate_ncp_cipher_list("AES-256-GCM:vollbit", &gc), NULL);
    assert_ptr_equal(mutate_ncp_cipher_list("", &gc), NULL);

    assert_ptr_equal(mutate_ncp_cipher_list(
                         "ChaCha20-Poly1305:ChaCha20-Poly1305:ChaCha20-Poly1305:"
                         "ChaCha20-Poly1305:ChaCha20-Poly1305:ChaCha20-Poly1305:"
                         "ChaCha20-Poly1305", &gc), NULL);

#ifdef ENABLE_CRYPTO_OPENSSL
    assert_string_equal(mutate_ncp_cipher_list("id-aes128-GCM:id-aes256-GCM",
                                               &gc), "AES-128-GCM:AES-256-GCM");
#else
    if (have_blowfish)
    {
        assert_string_equal(mutate_ncp_cipher_list("BLOWFISH-CBC",
                                                   &gc), "BF-CBC");
    }
#endif
    gc_free(&gc);
}

static void
test_extract_client_ciphers(void **state)
{
    struct gc_arena gc = gc_new();
    const char *client_peer_info;
    const char *peer_list;

    client_peer_info = "foo=bar\nIV_foo=y\nIV_NCP=2";
    peer_list = tls_peer_ncp_list(client_peer_info, &gc);
    assert_string_equal(aes_ciphers, peer_list);
    assert_true(tls_peer_supports_ncp(client_peer_info));

    client_peer_info = "foo=bar\nIV_foo=y\nIV_NCP=2\nIV_CIPHERS=BF-CBC";
    peer_list = tls_peer_ncp_list(client_peer_info, &gc);
    assert_string_equal("BF-CBC", peer_list);
    assert_true(tls_peer_supports_ncp(client_peer_info));

    client_peer_info = "IV_NCP=2\nIV_CIPHERS=BF-CBC:FOO-BAR\nIV_BAR=7";
    peer_list = tls_peer_ncp_list(client_peer_info, &gc);
    assert_string_equal("BF-CBC:FOO-BAR", peer_list);
    assert_true(tls_peer_supports_ncp(client_peer_info));

    client_peer_info = "IV_CIPHERS=BF-CBC:FOO-BAR\nIV_BAR=7";
    peer_list = tls_peer_ncp_list(client_peer_info, &gc);
    assert_string_equal("BF-CBC:FOO-BAR", peer_list);
    assert_true(tls_peer_supports_ncp(client_peer_info));

    client_peer_info = "IV_YOLO=NO\nIV_BAR=7";
    peer_list = tls_peer_ncp_list(client_peer_info, &gc);
    assert_string_equal("", peer_list);
    assert_false(tls_peer_supports_ncp(client_peer_info));

    peer_list = tls_peer_ncp_list(NULL, &gc);
    assert_string_equal("", peer_list);
    assert_false(tls_peer_supports_ncp(client_peer_info));

    gc_free(&gc);
}

static void
test_poor_man(void **state)
{
    struct gc_arena gc = gc_new();
    char *best_cipher;

    const char *serverlist = "CHACHA20_POLY1305:AES-128-GCM";
    const char *serverlistbfcbc = "CHACHA20_POLY1305:AES-128-GCM:BF-CBC:none";

    best_cipher = ncp_get_best_cipher(serverlist,
                                      "IV_YOLO=NO\nIV_BAR=7",
                                      "BF-CBC", &gc);

    assert_ptr_equal(best_cipher, NULL);


    best_cipher = ncp_get_best_cipher(serverlistbfcbc,
                                      "IV_YOLO=NO\nIV_BAR=7",
                                      "BF-CBC", &gc);

    assert_string_equal(best_cipher, "BF-CBC");


    best_cipher = ncp_get_best_cipher(serverlist,
                                      "IV_NCP=1\nIV_BAR=7",
                                      "AES-128-GCM", &gc);

    assert_string_equal(best_cipher, "AES-128-GCM");

    best_cipher = ncp_get_best_cipher(serverlist, NULL,
                                      "AES-128-GCM", &gc);

    assert_string_equal(best_cipher, "AES-128-GCM");

    best_cipher = ncp_get_best_cipher(serverlist, NULL,
                                      "none", &gc);
    assert_ptr_equal(best_cipher, NULL);

    best_cipher = ncp_get_best_cipher(serverlistbfcbc, NULL,
                                      "none", &gc);
    assert_string_equal(best_cipher, "none");

    best_cipher = ncp_get_best_cipher(serverlist, NULL, NULL, &gc);
    assert_ptr_equal(best_cipher, NULL);

    gc_free(&gc);
}


static void
test_ncp_best(void **state)
{
    struct gc_arena gc = gc_new();
    char *best_cipher;

    const char *serverlist = "CHACHA20_POLY1305:AES-128-GCM:AES-256-GCM";

    best_cipher = ncp_get_best_cipher(serverlist,
                                      "IV_YOLO=NO\nIV_NCP=2\nIV_BAR=7",
                                      "BF-CBC", &gc);

    assert_string_equal(best_cipher, "AES-128-GCM");

    /* Best cipher is in --cipher of client */
    best_cipher = ncp_get_best_cipher(serverlist, "IV_NCP=2\nIV_BAR=7",
                                      "CHACHA20_POLY1305", &gc);

    assert_string_equal(best_cipher, "CHACHA20_POLY1305");

    /* Best cipher is in --cipher of client */
    best_cipher = ncp_get_best_cipher(serverlist, "IV_CIPHERS=AES-128-GCM",
                                      "AES-256-CBC", &gc);


    assert_string_equal(best_cipher, "AES-128-GCM");

    /* IV_NCP=2 should be ignored if IV_CIPHERS is sent */
    best_cipher = ncp_get_best_cipher(serverlist,
                                      "IV_FOO=7\nIV_CIPHERS=AES-256-GCM\nIV_NCP=2",
                                      "AES-256-CBC", &gc);

    assert_string_equal(best_cipher, "AES-256-GCM");


    gc_free(&gc);
}

static void
test_ncp_default(void **state)
{
    bool have_chacha = cipher_valid("CHACHA20-POLY1305");

    struct options o = { 0 };

    o.gc = gc_new();

    /* no user specified string */
    o.ncp_ciphers = NULL;
    options_postprocess_setdefault_ncpciphers(&o);

    if (have_chacha)
    {
        assert_string_equal(o.ncp_ciphers, "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305");
    }
    else
    {
        assert_string_equal(o.ncp_ciphers, "AES-256-GCM:AES-128-GCM");
    }
    assert_string_equal(o.ncp_ciphers_conf, "DEFAULT");

    /* check that a default string is replaced with DEFAULT */
    if (have_chacha)
    {
        o.ncp_ciphers = "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305";
    }
    else
    {
        o.ncp_ciphers = "AES-256-GCM:AES-128-GCM";
    }

    options_postprocess_setdefault_ncpciphers(&o);
    assert_string_equal(o.ncp_ciphers_conf, "DEFAULT");

    /* test default in the middle of the string */
    o.ncp_ciphers = "BF-CBC:DEFAULT:AES-128-CBC:AES-256-CBC";
    options_postprocess_setdefault_ncpciphers(&o);

    if (have_chacha)
    {
        assert_string_equal(o.ncp_ciphers, "BF-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC:AES-256-CBC");
    }
    else
    {
        assert_string_equal(o.ncp_ciphers, "BF-CBC:AES-256-GCM:AES-128-GCM:AES-128-CBC:AES-256-CBC");
    }
    assert_string_equal(o.ncp_ciphers_conf, "BF-CBC:DEFAULT:AES-128-CBC:AES-256-CBC");

    /* string at the beginning */
    o.ncp_ciphers = "DEFAULT:AES-128-CBC:AES-192-CBC";
    options_postprocess_setdefault_ncpciphers(&o);

    if (have_chacha)
    {
        assert_string_equal(o.ncp_ciphers, "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC:AES-192-CBC");
    }
    else
    {
        assert_string_equal(o.ncp_ciphers, "AES-256-GCM:AES-128-GCM:AES-128-CBC:AES-192-CBC");
    }
    assert_string_equal(o.ncp_ciphers_conf, "DEFAULT:AES-128-CBC:AES-192-CBC");

    /* DEFAULT at the end */
    o.ncp_ciphers = "AES-192-GCM:AES-128-CBC:DEFAULT";
    options_postprocess_setdefault_ncpciphers(&o);

    if (have_chacha)
    {
        assert_string_equal(o.ncp_ciphers, "AES-192-GCM:AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305");
    }
    else
    {
        assert_string_equal(o.ncp_ciphers, "AES-192-GCM:AES-128-CBC:AES-256-GCM:AES-128-GCM");
    }
    assert_string_equal(o.ncp_ciphers_conf, "AES-192-GCM:AES-128-CBC:DEFAULT");

    gc_free(&o.gc);
}

static void
test_ncp_expand(void **state)
{
    bool have_chacha = cipher_valid("CHACHA20-POLY1305");
    struct options o = {0};

    o.gc = gc_new();
    struct gc_arena gc = gc_new();

    /* no user specified string */
    o.ncp_ciphers = NULL;
    options_postprocess_setdefault_ncpciphers(&o);

    const char *expanded = ncp_expanded_ciphers(&o, &gc);

    /* user specificed string with DEFAULT in it */
    o.ncp_ciphers = "AES-192-GCM:DEFAULT";
    options_postprocess_setdefault_ncpciphers(&o);
    const char *expanded2 = ncp_expanded_ciphers(&o, &gc);

    if (have_chacha)
    {
        assert_string_equal(expanded, " (AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305)");
        assert_string_equal(expanded2, " (AES-192-GCM:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305)");
    }
    else
    {
        assert_string_equal(expanded, " (AES-256-GCM:AES-128-GCM)");
        assert_string_equal(expanded2, " (AES-192-GCM:AES-256-GCM:AES-128-GCM)");
    }

    o.ncp_ciphers = "AES-192-GCM:BF-CBC";
    options_postprocess_setdefault_ncpciphers(&o);

    assert_string_equal(ncp_expanded_ciphers(&o, &gc), "");

    gc_free(&o.gc);
    gc_free(&gc);
}


const struct CMUnitTest ncp_tests[] = {
    cmocka_unit_test(test_check_ncp_ciphers_list),
    cmocka_unit_test(test_extract_client_ciphers),
    cmocka_unit_test(test_poor_man),
    cmocka_unit_test(test_ncp_best),
    cmocka_unit_test(test_ncp_default),
    cmocka_unit_test(test_ncp_expand),
};


int
main(void)
{
    openvpn_unit_test_setup();
#if defined(ENABLE_CRYPTO_OPENSSL)
    OpenSSL_add_all_algorithms();
#endif
    return cmocka_run_group_tests(ncp_tests, NULL, NULL);
}
