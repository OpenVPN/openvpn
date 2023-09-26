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

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>


#include "errlevel.h"
#include "error.h"

unsigned int x_debug_level = 0; /* Default to (almost) no debugging output */
bool fatal_error_triggered = false;

void
mock_set_debug_level(int level)
{
    x_debug_level = level;
}

void
x_msg_va(const unsigned int flags, const char *format,
         va_list arglist)
{
    if (flags & M_FATAL)
    {
        fatal_error_triggered = true;
        printf("FATAL ERROR:");
    }
    vprintf(format, arglist);
    printf("\n");
}

void
x_msg(const unsigned int flags, const char *format, ...)
{
    va_list arglist;
    va_start(arglist, format);
    x_msg_va(flags, format, arglist);
    va_end(arglist);
}

void
assert_failed(const char *filename, int line, const char *condition)
{
    mock_assert(false, condition ? condition : "", filename, line);
    /* Keep compiler happy.  Should not happen, mock_assert() does not return */
    exit(1);
}

/*
 * Fail memory allocation.  Don't use msg() because it tries
 * to allocate memory as part of its operation.
 */
void
out_of_memory(void)
{
    fprintf(stderr, "Out of Memory\n");
    exit(1);
}

bool
dont_mute(unsigned int flags)
{
    return true;
}
