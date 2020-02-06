/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
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
 *
 *
 *  A printf-like function (that only recognizes a subset of standard printf
 *  format operators) that prints arguments to an argv list instead
 *  of a standard string.  This is used to build up argv arrays for passing
 *  to execve.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "argv.h"
#include "integer.h"
#include "env_set.h"
#include "options.h"

static void
argv_extend(struct argv *a, const size_t newcap)
{
    if (newcap > a->capacity)
    {
        char **newargv;
        size_t i;
        ALLOC_ARRAY_CLEAR(newargv, char *, newcap);
        for (i = 0; i < a->argc; ++i)
        {
            newargv[i] = a->argv[i];
        }
        free(a->argv);
        a->argv = newargv;
        a->capacity = newcap;
    }
}

static void
argv_init(struct argv *a)
{
    a->capacity = 0;
    a->argc = 0;
    a->argv = NULL;
    argv_extend(a, 8);
}

struct argv
argv_new(void)
{
    struct argv ret;
    argv_init(&ret);
    return ret;
}

void
argv_free(struct argv *a)
{
    size_t i;
    for (i = 0; i < a->argc; ++i)
    {
        free(a->argv[i]);
    }
    free(a->argv);
}

static void
argv_reset(struct argv *a)
{
    size_t i;
    for (i = 0; i < a->argc; ++i)
    {
        free(a->argv[i]);
        a->argv[i] = NULL;
    }
    a->argc = 0;
}

static void
argv_grow(struct argv *a, const size_t add)
{
    const size_t newargc = a->argc + add + 1;
    ASSERT(newargc > a->argc);
    argv_extend(a, adjust_power_of_2(newargc));
}

static void
argv_append(struct argv *a, char *str)  /* str must have been malloced or be NULL */
{
    argv_grow(a, 1);
    a->argv[a->argc++] = str;
}

static struct argv
argv_clone(const struct argv *a, const size_t headroom)
{
    struct argv r;
    argv_init(&r);

    for (size_t i = 0; i < headroom; ++i)
    {
        argv_append(&r, NULL);
    }
    if (a)
    {
        for (size_t i = 0; i < a->argc; ++i)
        {
            argv_append(&r, string_alloc(a->argv[i], NULL));
        }
    }
    return r;
}

struct argv
argv_insert_head(const struct argv *a, const char *head)
{
    struct argv r;
    r = argv_clone(a, 1);
    r.argv[0] = string_alloc(head, NULL);
    return r;
}

const char *
argv_str(const struct argv *a, struct gc_arena *gc, const unsigned int flags)
{
    return print_argv((const char **)a->argv, gc, flags);
}

void
argv_msg(const int msglev, const struct argv *a)
{
    struct gc_arena gc = gc_new();
    msg(msglev, "%s", argv_str(a, &gc, 0));
    gc_free(&gc);
}

void
argv_msg_prefix(const int msglev, const struct argv *a, const char *prefix)
{
    struct gc_arena gc = gc_new();
    msg(msglev, "%s: %s", prefix, argv_str(a, &gc, 0));
    gc_free(&gc);
}


/*
 * argv_prep_format - prepare argv format string for further processing
 *
 * Individual argument must be separated by space. Ignores leading and trailing spaces.
 * Consecutive spaces count as one. Returns prepared format string, with space replaced
 * by delim and adds the number of arguments to the count parameter.
 */
static char *
argv_prep_format(const char *format, const char delim, size_t *count, struct gc_arena *gc)
{
    if (format == NULL)
    {
        return NULL;
    }

    bool in_token = false;
    char *f = gc_malloc(strlen(format) + 1, true, gc);
    for (int i = 0, j = 0; i < strlen(format); i++)
    {
        if (format[i] == ' ')
        {
            in_token = false;
            continue;
        }

        if (!in_token)
        {
            (*count)++;

            /*
             * We don't add any delimiter to the output string if
             * the string is empty; the resulting format string
             * will never start with a delimiter.
             */
            if (j > 0)  /* Has anything been written to the output string? */
            {
                f[j++] = delim;
            }
        }

        f[j++] = format[i];
        in_token = true;
    }

    return f;
}

/*
 * argv_printf_arglist - create a struct argv from a format string
 *
 * Instead of parsing the format string ourselves place delimiters via argv_prep_format()
 * before we let libc's printf() do the parsing. Then split the resulting string at the
 * injected delimiters.
 */
static bool
argv_printf_arglist(struct argv *a, const char *format, va_list arglist)
{
    struct gc_arena gc = gc_new();
    const char delim = 0x1D;  /* ASCII Group Separator (GS) */
    bool res = false;

    /*
     * Prepare a format string which will be used by vsnprintf() later on.
     *
     * This means all space separators in the input format string will be
     * replaced by the GS (0x1D), so we can split this up again after the
     * the vsnprintf() call into individual arguments again which will be
     * saved in the struct argv.
     *
     */
    size_t argc = a->argc;
    char *f = argv_prep_format(format, delim, &argc, &gc);
    if (f == NULL)
    {
        goto out;
    }

    /* determine minimum buffer size */
    va_list tmplist;
    va_copy(tmplist, arglist);
    int len = vsnprintf(NULL, 0, f, tmplist);
    va_end(tmplist);
    if (len < 0)
    {
        goto out;
    }

    /*
     *  Do the actual vsnprintf() operation, which expands the format
     *  string with the provided arguments.
     */
    size_t size = len + 1;
    char *buf = gc_malloc(size, false, &gc);
    len = vsnprintf(buf, size, f, arglist);
    if (len < 0 || len >= size)
    {
        goto out;
    }

    /*
     * Split the string at the GS (0x1D) delimiters and put each elemen
     * into the struct argv being returned to the caller.
     */
    char *end = strchr(buf, delim);
    while (end)
    {
        *end = '\0';
        argv_append(a, string_alloc(buf, NULL));
        buf = end + 1;
        end = strchr(buf, delim);
    }
    argv_append(a, string_alloc(buf, NULL));

    if (a->argc != argc)
    {
        /* Someone snuck in a GS (0x1D), fail gracefully */
        argv_reset(a);
        goto out;
    }
    res = true;

out:
    gc_free(&gc);
    return res;
}



bool
argv_printf(struct argv *a, const char *format, ...)
{
    va_list arglist;
    va_start(arglist, format);

    argv_reset(a);
    bool res = argv_printf_arglist(a, format, arglist);
    va_end(arglist);
    return res;
}

bool
argv_printf_cat(struct argv *a, const char *format, ...)
{
    va_list arglist;
    va_start(arglist, format);

    bool res = argv_printf_arglist(a, format, arglist);
    va_end(arglist);
    return res;
}

void
argv_parse_cmd(struct argv *a, const char *s)
{
    argv_reset(a);

    struct gc_arena gc = gc_new();
    char *parms[MAX_PARMS + 1] = { 0 };
    int nparms = parse_line(s, parms, MAX_PARMS, "SCRIPT-ARGV", 0, D_ARGV_PARSE_CMD, &gc);
    if (nparms)
    {
        int i;
        for (i = 0; i < nparms; ++i)
        {
            argv_append(a, string_alloc(parms[i], NULL));
        }
    }
    else
    {
        argv_append(a, string_alloc(s, NULL));
    }

    gc_free(&gc);
}
