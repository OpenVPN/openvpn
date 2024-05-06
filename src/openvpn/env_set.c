/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2014-2015 David Sommerseth <davids@redhat.com>
 *  Copyright (C) 2016-2024 David Sommerseth <davids@openvpn.net>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "env_set.h"

#include "run_command.h"

/*
 * Set environmental variable (int or string).
 *
 * On Posix, we use putenv for portability,
 * and put up with its painful semantics
 * that require all the support code below.
 */

/* General-purpose environmental variable set functions */

static char *
construct_name_value(const char *name, const char *value, struct gc_arena *gc)
{
    struct buffer out;

    ASSERT(name);
    if (!value)
    {
        value = "";
    }
    out = alloc_buf_gc(strlen(name) + strlen(value) + 2, gc);
    buf_printf(&out, "%s=%s", name, value);
    return BSTR(&out);
}

static bool
env_string_equal(const char *s1, const char *s2)
{
    int c1, c2;
    ASSERT(s1);
    ASSERT(s2);

    while (true)
    {
        c1 = *s1++;
        c2 = *s2++;
        if (c1 == '=')
        {
            c1 = 0;
        }
        if (c2 == '=')
        {
            c2 = 0;
        }
        if (!c1 && !c2)
        {
            return true;
        }
        if (c1 != c2)
        {
            break;
        }
    }
    return false;
}

static bool
remove_env_item(const char *str, const bool do_free, struct env_item **list)
{
    struct env_item *current, *prev;

    ASSERT(str);
    ASSERT(list);

    for (current = *list, prev = NULL; current != NULL; current = current->next)
    {
        if (env_string_equal(current->string, str))
        {
            if (prev)
            {
                prev->next = current->next;
            }
            else
            {
                *list = current->next;
            }
            if (do_free)
            {
                secure_memzero(current->string, strlen(current->string));
                free(current->string);
                free(current);
            }
            return true;
        }
        prev = current;
    }
    return false;
}

static void
add_env_item(char *str, const bool do_alloc, struct env_item **list, struct gc_arena *gc)
{
    struct env_item *item;

    ASSERT(str);
    ASSERT(list);

    ALLOC_OBJ_GC(item, struct env_item, gc);
    item->string = do_alloc ? string_alloc(str, gc) : str;
    item->next = *list;
    *list = item;
}

/* struct env_set functions */

static bool
env_set_del_nolock(struct env_set *es, const char *str)
{
    return remove_env_item(str, es->gc == NULL, &es->list);
}

static void
env_set_add_nolock(struct env_set *es, const char *str)
{
    remove_env_item(str, es->gc == NULL, &es->list);
    add_env_item((char *)str, true, &es->list, es->gc);
}

struct env_set *
env_set_create(struct gc_arena *gc)
{
    struct env_set *es;
    ALLOC_OBJ_CLEAR_GC(es, struct env_set, gc);
    es->list = NULL;
    es->gc = gc;
    return es;
}

void
env_set_destroy(struct env_set *es)
{
    if (es && es->gc == NULL)
    {
        struct env_item *e = es->list;
        while (e)
        {
            struct env_item *next = e->next;
            free(e->string);
            free(e);
            e = next;
        }
        free(es);
    }
}

bool
env_set_del(struct env_set *es, const char *str)
{
    bool ret;
    ASSERT(es);
    ASSERT(str);
    ret = env_set_del_nolock(es, str);
    return ret;
}

void
env_set_add(struct env_set *es, const char *str)
{
    ASSERT(es);
    ASSERT(str);
    env_set_add_nolock(es, str);
}

const char *
env_set_get(const struct env_set *es, const char *name)
{
    const struct env_item *item = es->list;
    while (item && !env_string_equal(item->string, name))
    {
        item = item->next;
    }
    return item ? item->string : NULL;
}

void
env_set_print(int msglevel, const struct env_set *es)
{
    if (check_debug_level(msglevel))
    {
        const struct env_item *e;
        int i;

        if (es)
        {
            e = es->list;
            i = 0;

            while (e)
            {
                if (env_safe_to_print(e->string))
                {
                    msg(msglevel, "ENV [%d] '%s'", i, e->string);
                }
                ++i;
                e = e->next;
            }
        }
    }
}

void
env_set_inherit(struct env_set *es, const struct env_set *src)
{
    const struct env_item *e;

    ASSERT(es);

    if (src)
    {
        e = src->list;
        while (e)
        {
            env_set_add_nolock(es, e->string);
            e = e->next;
        }
    }
}


/* add/modify/delete environmental strings */

void
setenv_counter(struct env_set *es, const char *name, counter_type value)
{
    char buf[64];
    snprintf(buf, sizeof(buf), counter_format, value);
    setenv_str(es, name, buf);
}

void
setenv_int(struct env_set *es, const char *name, int value)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%d", value);
    setenv_str(es, name, buf);
}

void
setenv_long_long(struct env_set *es, const char *name, long long value)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%" PRIi64, (int64_t)value);
    setenv_str(es, name, buf);
}

void
setenv_str(struct env_set *es, const char *name, const char *value)
{
    setenv_str_ex(es, name, value, CC_NAME, 0, 0, CC_PRINT, 0, 0);
}

void
setenv_str_safe(struct env_set *es, const char *name, const char *value)
{
    uint8_t b[64];
    struct buffer buf;
    buf_set_write(&buf, b, sizeof(b));
    if (buf_printf(&buf, "OPENVPN_%s", name))
    {
        setenv_str(es, BSTR(&buf), value);
    }
    else
    {
        msg(M_WARN, "setenv_str_safe: name overflow");
    }
}

void
setenv_str_incr(struct env_set *es, const char *name, const char *value)
{
    unsigned int counter = 1;
    const size_t tmpname_len = strlen(name) + 5; /* 3 digits counter max */
    char *tmpname = gc_malloc(tmpname_len, true, NULL);
    strcpy(tmpname, name);
    while (NULL != env_set_get(es, tmpname) && counter < 1000)
    {
        ASSERT(snprintf(tmpname, tmpname_len, "%s_%u", name, counter));
        counter++;
    }
    if (counter < 1000)
    {
        setenv_str(es, tmpname, value);
    }
    else
    {
        msg(D_TLS_DEBUG_MED, "Too many same-name env variables, ignoring: %s", name);
    }
    free(tmpname);
}

void
setenv_del(struct env_set *es, const char *name)
{
    ASSERT(name);
    setenv_str(es, name, NULL);
}

void
setenv_str_ex(struct env_set *es,
              const char *name,
              const char *value,
              const unsigned int name_include,
              const unsigned int name_exclude,
              const char name_replace,
              const unsigned int value_include,
              const unsigned int value_exclude,
              const char value_replace)
{
    struct gc_arena gc = gc_new();
    const char *name_tmp;
    const char *val_tmp = NULL;

    ASSERT(name && strlen(name) > 1);

    name_tmp = string_mod_const(name, name_include, name_exclude, name_replace, &gc);

    if (value)
    {
        val_tmp = string_mod_const(value, value_include, value_exclude, value_replace, &gc);
    }

    ASSERT(es);

    if (val_tmp)
    {
        const char *str = construct_name_value(name_tmp, val_tmp, &gc);
        env_set_add(es, str);
#if DEBUG_VERBOSE_SETENV
        msg(M_INFO, "SETENV_ES '%s'", str);
#endif
    }
    else
    {
        env_set_del(es, name_tmp);
    }

    gc_free(&gc);
}

/*
 * Setenv functions that append an integer index to the name
 */
static const char *
setenv_format_indexed_name(const char *name, const int i, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(strlen(name) + 16, gc);
    if (i >= 0)
    {
        buf_printf(&out, "%s_%d", name, i);
    }
    else
    {
        buf_printf(&out, "%s", name);
    }
    return BSTR(&out);
}

void
setenv_int_i(struct env_set *es, const char *name, const int value, const int i)
{
    struct gc_arena gc = gc_new();
    const char *name_str = setenv_format_indexed_name(name, i, &gc);
    setenv_int(es, name_str, value);
    gc_free(&gc);
}

void
setenv_str_i(struct env_set *es, const char *name, const char *value, const int i)
{
    struct gc_arena gc = gc_new();
    const char *name_str = setenv_format_indexed_name(name, i, &gc);
    setenv_str(es, name_str, value);
    gc_free(&gc);
}

bool
env_allowed(const char *str)
{
    return (script_security() >= SSEC_PW_ENV || !is_password_env_var(str));
}

/* Make arrays of strings */

const char **
make_env_array(const struct env_set *es,
               const bool check_allowed,
               struct gc_arena *gc)
{
    char **ret = NULL;
    struct env_item *e = NULL;
    int i = 0, n = 0;

    /* figure length of es */
    if (es)
    {
        for (e = es->list; e != NULL; e = e->next)
        {
            ++n;
        }
    }

    /* alloc return array */
    ALLOC_ARRAY_CLEAR_GC(ret, char *, n+1, gc);

    /* fill return array */
    if (es)
    {
        i = 0;
        for (e = es->list; e != NULL; e = e->next)
        {
            if (!check_allowed || env_allowed(e->string))
            {
                ASSERT(i < n);
                ret[i++] = e->string;
            }
        }
    }

    ret[i] = NULL;
    return (const char **)ret;
}
