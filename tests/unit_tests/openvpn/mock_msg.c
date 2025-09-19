/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2021 Sentyron B.V. <openvpn@sentyron.com>
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

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <stdint.h>
#ifndef NO_CMOCKA
#include <cmocka.h>
#endif

#include "errlevel.h"
#include "error.h"
#include "mock_msg.h"

msglvl_t x_debug_level = 0; /* Default to (almost) no debugging output */
msglvl_t print_x_debug_level = 0;

bool fatal_error_triggered = false;

char mock_msg_buf[MOCK_MSG_BUF];


void
mock_set_debug_level(msglvl_t level)
{
    x_debug_level = level;
}

msglvl_t
mock_get_debug_level(void)
{
    return x_debug_level;
}

void
mock_set_print_debug_level(msglvl_t level)
{
    print_x_debug_level = level;
}

msglvl_t
get_debug_level(void)
{
    return x_debug_level;
}

void
x_msg_va(const msglvl_t flags, const char *format, va_list arglist)
{
    if (flags & M_FATAL)
    {
        fatal_error_triggered = true;
        printf("FATAL ERROR:");
    }
    CLEAR(mock_msg_buf);
    vsnprintf(mock_msg_buf, sizeof(mock_msg_buf), format, arglist);

    if ((flags & M_DEBUG_LEVEL) <= print_x_debug_level)
    {
        printf("%s", mock_msg_buf);
        printf("\n");
    }
}

void
x_msg(const msglvl_t flags, const char *format, ...)
{
    va_list arglist;
    va_start(arglist, format);
    x_msg_va(flags, format, arglist);
    va_end(arglist);
}

/* Allow to use mock_msg.c outside of UT */
#ifndef NO_CMOCKA
void
assert_failed(const char *filename, int line, const char *condition)
{
    mock_assert(false, condition ? condition : "", filename, line);
    /* Keep compiler happy.  Should not happen, mock_assert() does not return */
    exit(1);
}
#else /* ifndef NO_CMOCKA */
void
assert_failed(const char *filename, int line, const char *condition)
{
    msg(M_FATAL, "Assertion failed at %s:%d (%s)", filename, line, condition ? condition : "");
    _exit(1);
}
#endif


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
dont_mute(msglvl_t flags)
{
    return true;
}
