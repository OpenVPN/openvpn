/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2019 Arne Schwabe <arne@rfc2549.org>
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

#include "ssl_ncp.c"

/* Defines for use in the tests and the mock parse_line() */

const char *bf_chacha = "BF-CBC:CHACHA20-POLY1305";
const char *aes_ciphers = "AES-256-GCM:AES-128-GCM";

static void
test_check_ncp_ciphers_list(void **state)
{
    bool have_chacha = cipher_kt_get("CHACHA20-POLY1305");

    assert_true(tls_check_ncp_cipher_list(aes_ciphers));
    assert_true(have_chacha == tls_check_ncp_cipher_list(bf_chacha));
    assert_false(tls_check_ncp_cipher_list("vollbit"));
    assert_false(tls_check_ncp_cipher_list("AES-256-GCM:vollbit"));
}

static void
test_extract_client_ciphers(void **state)
{
    struct gc_arena gc = gc_new();
    const char *client_peer_info;
    const char *peer_list;

    client_peer_info = "foo=bar\nIV_foo=y\nIV_NCP=2";
    peer_list = tls_peer_ncp_list(client_peer_info, &gc);
    assert_string_equal(aes_ciphers,peer_list);
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

    const char *serverlist="CHACHA20_POLY1305:AES-128-GCM";

    best_cipher = ncp_get_best_cipher(serverlist, "BF-CBC",
                                      "IV_YOLO=NO\nIV_BAR=7",
                                      "BF-CBC", &gc);

    assert_string_equal(best_cipher, "BF-CBC");

    best_cipher = ncp_get_best_cipher(serverlist, "BF-CBC",
                                      "IV_NCP=1\nIV_BAR=7",
                                      "AES-128-GCM", &gc);

    assert_string_equal(best_cipher, "AES-128-GCM");

    best_cipher = ncp_get_best_cipher(serverlist, "BF-CBC",
                                      NULL,
                                      "AES-128-GCM", &gc);

    assert_string_equal(best_cipher, "AES-128-GCM");

    gc_free(&gc);
}


static void
test_ncp_best(void **state)
{
    struct gc_arena gc = gc_new();
    char *best_cipher;

    const char *serverlist="CHACHA20_POLY1305:AES-128-GCM:AES-256-GCM";

    best_cipher = ncp_get_best_cipher(serverlist, "BF-CBC",
                                      "IV_YOLO=NO\nIV_NCP=2\nIV_BAR=7",
                                      "BF-CBC", &gc);

    assert_string_equal(best_cipher, "AES-128-GCM");

    /* Best cipher is in --cipher of client */
    best_cipher = ncp_get_best_cipher(serverlist, "BF-CBC",
                                      "IV_NCP=2\nIV_BAR=7",
                                      "CHACHA20_POLY1305", &gc);

    assert_string_equal(best_cipher, "CHACHA20_POLY1305");

    /* Best cipher is in --cipher of client */
    best_cipher = ncp_get_best_cipher(serverlist, "BF-CBC",
                                      "IV_CIPHERS=AES-128-GCM",
                                      "AES-256-CBC", &gc);


    assert_string_equal(best_cipher, "AES-128-GCM");

    /* IV_NCP=2 should be ignored if IV_CIPHERS is sent */
    best_cipher = ncp_get_best_cipher(serverlist, "BF-CBC",
                                      "IV_FOO=7\nIV_CIPHERS=AES-256-GCM\nIV_NCP=2",
                                      "AES-256-CBC", &gc);

    assert_string_equal(best_cipher, "AES-256-GCM");


    gc_free(&gc);
}




const struct CMUnitTest ncp_tests[] = {
    cmocka_unit_test(test_check_ncp_ciphers_list),
    cmocka_unit_test(test_extract_client_ciphers),
    cmocka_unit_test(test_poor_man),
    cmocka_unit_test(test_ncp_best)
};


int main(void)
{
#if defined(ENABLE_CRYPTO_OPENSSL)
    OpenSSL_add_all_algorithms();
#endif
    return cmocka_run_group_tests(ncp_tests, NULL, NULL);
}
