/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
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

/*
 * Win32-specific OpenVPN code, targeted at the mingw
 * development environment.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#ifdef _WIN32

#include "buffer.h"
#include "win32-util.h"

WCHAR *
wide_string(const char *utf8, struct gc_arena *gc)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    WCHAR *ucs16 = gc_malloc(n * sizeof(WCHAR), false, gc);
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, ucs16, n);
    return ucs16;
}


/*
 * Return true if filename is safe to be used on Windows,
 * by avoiding the following reserved names:
 *
 * CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9,
 * LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, LPT9, and CLOCK$
 *
 * See: http://msdn.microsoft.com/en-us/library/aa365247.aspx
 *  and http://msdn.microsoft.com/en-us/library/86k9f82k(VS.80).aspx
 */

static bool
cmp_prefix(const char *str, const bool n, const char *pre)
{
    size_t i = 0;

    if (!str)
    {
        return false;
    }

    while (true)
    {
        const int c1 = pre[i];
        int c2 = str[i];
        ++i;
        if (c1 == '\0')
        {
            if (n)
            {
                if (isdigit(c2))
                {
                    c2 = str[i];
                }
                else
                {
                    return false;
                }
            }
            return c2 == '\0' || c2 == '.';
        }
        else if (c2 == '\0')
        {
            return false;
        }
        if (c1 != tolower(c2))
        {
            return false;
        }
    }
}

bool
win_safe_filename(const char *fn)
{
    if (cmp_prefix(fn, false, "con"))
    {
        return false;
    }
    if (cmp_prefix(fn, false, "prn"))
    {
        return false;
    }
    if (cmp_prefix(fn, false, "aux"))
    {
        return false;
    }
    if (cmp_prefix(fn, false, "nul"))
    {
        return false;
    }
    if (cmp_prefix(fn, true, "com"))
    {
        return false;
    }
    if (cmp_prefix(fn, true, "lpt"))
    {
        return false;
    }
    if (cmp_prefix(fn, false, "clock$"))
    {
        return false;
    }
    return true;
}
#endif /* _WIN32 */
