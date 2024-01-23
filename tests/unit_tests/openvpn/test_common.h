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

#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>

/**
 * Sets up the environment for unit tests like making both stderr and stdout
 * non-buffered to avoid messages getting lost if the program exits early.
 *
 * This has a openvpn prefix to avoid confusion with cmocka's unit_test_setup_*
 * methods
 */
void
openvpn_unit_test_setup()
{
    assert_int_equal(setvbuf(stdout, NULL, _IONBF, BUFSIZ), 0);
    assert_int_equal(setvbuf(stderr, NULL, _IONBF, BUFSIZ), 0);
}
