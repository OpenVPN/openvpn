/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2023 Selva Nair <selva.nair@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by the
 *  Free Software Foundation, either version 2 of the License,
 *  or (at your option) any later version.
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
#include "manage.h"
#include "integer.h"
#include "xkey_common.h"

#if defined(HAVE_XKEY_PROVIDER) && defined (ENABLE_CRYPTOAPI)
#include <setjmp.h>
#include <cmocka.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

#include <cryptoapi.h>
#include <cryptoapi.c> /* pull-in the whole file to test static functions */

struct management *management; /* global */

/* mock a management function that xkey_provider needs */
char *
management_query_pk_sig(struct management *man, const char *b64_data,
                        const char *algorithm)
{
    (void) man;
    (void) b64_data;
    (void) algorithm;
    return NULL;
}

/* tls_libctx is defined in ssl_openssl.c which we do not want to compile in */
OSSL_LIB_CTX *tls_libctx;

#ifndef _countof
#define _countof(x) sizeof((x))/sizeof(*(x))
#endif

/* test data */
static const uint8_t test_hash[] = {
    0x77, 0x38, 0x65, 0x00, 0x1e, 0x96, 0x48, 0xc6, 0x57, 0x0b, 0xae,
    0xc0, 0xb7, 0x96, 0xf9, 0x66, 0x4d, 0x5f, 0xd0, 0xb7
};

/* valid test strings to test with and without embedded and trailing spaces */
static const char *valid_str[] = {
    "773865001e9648c6570baec0b796f9664d5fd0b7",
    " 77 386500 1e 96 48 c6570b aec0b7   96f9664d5f  d0 b7",
    "   773865001e9648c6570baec0b796f9664d5fd0b7  ",
};

/* some invalid strings to test */
static const char *invalid_str[] = {
    "773 865001e9648c6570baec0b796f9664d5fd0b7",  /* space within byte */
    "77:38:65001e9648c6570baec0b796f9664d5fd0b7", /* invalid separator */
    "7738x5001e9648c6570baec0b796f9664d5fd0b7",   /* non hex character */
};

static void
test_parse_hexstring(void **state)
{
    unsigned char hash[255];
    (void) state;

    for (int i = 0; i < _countof(valid_str); i++)
    {
        int len = parse_hexstring(valid_str[i], hash, _countof(hash));
        assert_int_equal(len, sizeof(test_hash));
        assert_memory_equal(hash, test_hash, sizeof(test_hash));
        memset(hash, 0, _countof(hash));
    }

    for (int i = 0; i < _countof(invalid_str); i++)
    {
        int len = parse_hexstring(invalid_str[i], hash, _countof(hash));
        assert_int_equal(len, 0);
    }
}

int
main(void)
{
    const struct CMUnitTest tests[] = { cmocka_unit_test(test_parse_hexstring) };

    int ret = cmocka_run_group_tests_name("cryptoapi tests", tests, NULL, NULL);

    return ret;
}

#else  /* ifdef HAVE_XKEY_PROVIDER */

int
main(void)
{
    return 0;
}

#endif  /* ifdef HAVE_XKEY_PROVIDER */
