/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2026 Sentyron B.V. <openvpn@sentyron.com>
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

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>

#if defined(ENABLE_CRYPTO_MBEDTLS)
#include "mbedtls_compat.h"
#endif

/* Do we use cmocka < 2.0.0? */
#ifndef HAVE_CMOCKA_VERSION_H
#define HAVE_OLD_CMOCKA_API 1
/* compat with various versions of cmocka.h
 * Older versions have LargestIntegralType. Newer
 * versions use uintmax_t. But LargestIntegralType
 * is not guaranteed to be equal to uintmax_t, so
 * we can't use that unconditionally. So we only use
 * it if cmocka.h does not define LargestIntegralType.
 */
#ifndef LargestIntegralType
#define LargestIntegralType uintmax_t
#endif
/* redefine 2.x API in terms of 1.x API */
#define CMockaValueData             LargestIntegralType
#define check_expected_uint         check_expected
#define expect_uint_value           expect_value
#define expect_check_data           expect_check
#define cast_ptr_to_cmocka_value(x) (x)
#endif

/**
 * Sets up the environment for unit tests like making both stderr and stdout
 * non-buffered to avoid messages getting lost if the program exits early.
 *
 * This has a openvpn prefix to avoid confusion with cmocka's unit_test_setup_*
 * methods
 */
static inline void
openvpn_unit_test_setup(void)
{
    assert_int_equal(setvbuf(stdout, NULL, _IONBF, BUFSIZ), 0);
    assert_int_equal(setvbuf(stderr, NULL, _IONBF, BUFSIZ), 0);
#if defined(ENABLE_CRYPTO_MBEDTLS)
    mbedtls_compat_psa_crypto_init();
#endif
}

/**
 * Helper function to get a file path from the unit test directory to open it
 * or pass its path to another function. This function will first look for
 * an environment variable or if failing that, will fall back to a hardcoded
 * value from compile time if compiled with CMake.
 *
 * @param buf           buffer holding the path to the file
 * @param bufsize       size of buf
 * @param filename      name of the filename to retrieve relative to the
 *                      unit test source directory
 */
void
openvpn_test_get_srcdir_dir(char *buf, size_t bufsize, const char *filename)
{
    const char *srcdir = getenv("srcdir");

#if defined(UNIT_TEST_SOURCEDIR)
    if (!srcdir)
    {
        srcdir = UNIT_TEST_SOURCEDIR;
    }
#endif
    assert_non_null(srcdir);

    snprintf(buf, bufsize, "%s/%s", srcdir, filename);
}
