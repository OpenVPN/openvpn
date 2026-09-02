/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
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

/*
 * Win32-specific OpenVPN code, targeted at the mingw
 * development environment.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
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

/* special to cmd.exe, which CreateProcess() uses to run .bat/.cmd (VU#123335) */
#define CMD_QUOTE_TRIGGERS " &|<>^%()!"

static bool
argv_element_needs_quotes(const char *str)
{
    for (const char *c = str; *c != '\0'; ++c)
    {
        if (strchr(CMD_QUOTE_TRIGGERS, *c) != NULL)
        {
            return true;
        }
    }
    return false;
}

WCHAR *
wide_cmd_line(const struct argv *a, struct gc_arena *gc)
{
    size_t nchars = 1;
    size_t maxlen = 0;
    size_t i;
    struct buffer buf;
    char *work = NULL;

    if (!a)
    {
        return NULL;
    }

    for (i = 0; i < a->argc; ++i)
    {
        const char *arg = a->argv[i];
        const size_t len = strlen(arg);
        nchars += len + 3;
        if (len > maxlen)
        {
            maxlen = len;
        }
    }

    work = gc_malloc(maxlen + 1, false, gc);
    check_malloc_return(work);
    buf = alloc_buf_gc(nchars, gc);

    for (i = 0; i < a->argc; ++i)
    {
        const char *arg = a->argv[i];
        strcpy(work, arg);
        string_mod(work, CC_PRINT, CC_DOUBLE_QUOTE | CC_CRLF, '_');
        if (i)
        {
            buf_printf(&buf, " ");
        }
        if (argv_element_needs_quotes(work))
        {
            buf_printf(&buf, "\"%s\"", work);
        }
        else
        {
            buf_printf(&buf, "%s", work);
        }
    }

    return wide_string(BSTR(&buf), gc);
}

char *
utf16to8(const wchar_t *utf16, struct gc_arena *gc)
{
    char *utf8 = NULL;
    int n = WideCharToMultiByte(CP_UTF8, 0, utf16, -1, NULL, 0, NULL, NULL);
    if (n > 0)
    {
        utf8 = gc_malloc(n, true, gc);
        if (utf8)
        {
            WideCharToMultiByte(CP_UTF8, 0, utf16, -1, utf8, n, NULL, NULL);
        }
    }
    return utf8;
}

/*
 * Return true if filename is safe to be used on Windows,
 * by avoiding the following reserved names:
 *
 * CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9,
 * LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, LPT9, and CLOCK$
 *
 * See: https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
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

const char *
win_get_tempdir(void)
{
    static char tmpdir[MAX_PATH];
    WCHAR wtmpdir[MAX_PATH];

    if (!GetTempPathW(_countof(wtmpdir), wtmpdir))
    {
        return NULL;
    }

    if (WideCharToMultiByte(CP_UTF8, 0, wtmpdir, -1, NULL, 0, NULL, NULL) > sizeof(tmpdir))
    {
        msg(M_WARN, "Could not get temporary directory. Path is too long."
                    "  Consider using --tmp-dir");
        return NULL;
    }

    WideCharToMultiByte(CP_UTF8, 0, wtmpdir, -1, tmpdir, sizeof(tmpdir), NULL, NULL);
    return tmpdir;
}

bool
win_path_in_dir(const WCHAR *path, const WCHAR *dir)
{
    size_t dir_len = wcslen(dir);
    /* dir_len <= 1 guards the dir[dir_len - 1] access below and rejects a
     * degenerate single-character directory (a normalized absolute path is
     * always longer). */
    if (dir_len <= 1 || wcsnicmp(dir, path, dir_len) != 0)
    {
        return false;
    }

    /* A plain prefix match is not sufficient: if dir is "C:\foo" then
     * "C:\foo_evil\bar.dll" shares the prefix but is not inside "C:\foo".
     * Require that the matched prefix ends on a path separator, i.e. either
     * dir already ends with a separator or the character following the prefix
     * in path is one. */
    if (dir[dir_len - 1] == L'\\' || dir[dir_len - 1] == L'/')
    {
        return true;
    }

    WCHAR next = path[dir_len];
    return next == L'\\' || next == L'/';
}

#endif /* _WIN32 */
