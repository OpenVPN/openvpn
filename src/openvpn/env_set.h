/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Technologies, Inc. <sales@openvpn.net>
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

#ifndef ENV_SET_H
#define ENV_SET_H

#include "argv.h"
#include "basic.h"
#include "buffer.h"
#include "common.h"

/*
 * Handle environmental variable lists
 */

struct env_item {
    char *string;
    struct env_item *next;
};

struct env_set {
    struct gc_arena *gc;
    struct env_item *list;
};

/* set/delete environmental variable */
void setenv_str_ex(struct env_set *es,
                   const char *name,
                   const char *value,
                   const unsigned int name_include,
                   const unsigned int name_exclude,
                   const char name_replace,
                   const unsigned int value_include,
                   const unsigned int value_exclude,
                   const char value_replace);

void setenv_counter(struct env_set *es, const char *name, counter_type value);

void setenv_int(struct env_set *es, const char *name, int value);

void setenv_long_long(struct env_set *es, const char *name, long long value);

void setenv_str(struct env_set *es, const char *name, const char *value);

void setenv_str_safe(struct env_set *es, const char *name, const char *value);

void setenv_del(struct env_set *es, const char *name);

/**
 * Store the supplied name value pair in the env_set.  If the variable with the
 * supplied name  already exists, append _N to the name, starting at N=1.
 */
void setenv_str_incr(struct env_set *es, const char *name, const char *value);

void setenv_int_i(struct env_set *es, const char *name, const int value, const int i);

void setenv_str_i(struct env_set *es, const char *name, const char *value, const int i);

/* struct env_set functions */

struct env_set *env_set_create(struct gc_arena *gc);

void env_set_destroy(struct env_set *es);

bool env_set_del(struct env_set *es, const char *str);

void env_set_add(struct env_set *es, const char *str);

const char *env_set_get(const struct env_set *es, const char *name);

void env_set_print(int msglevel, const struct env_set *es);

void env_set_inherit(struct env_set *es, const struct env_set *src);

/* returns true if environmental variable name starts with 'password' */
static inline bool
is_password_env_var(const char *str)
{
    return (strncmp(str, "password", 8) == 0);
}

/* returns true if environmental variable safe to print to log */
static inline bool
env_safe_to_print(const char *str)
{
#ifndef UNSAFE_DEBUG
    if (is_password_env_var(str))
    {
        return false;
    }
#endif
    return true;
}

/* returns true if environmental variable may be passed to an external program */
bool env_allowed(const char *str);

const char **make_env_array(const struct env_set *es,
                            const bool check_allowed,
                            struct gc_arena *gc);

#endif /* ifndef ENV_SET_H */
