/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
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

#ifndef CIRC_LIST_H
#define CIRC_LIST_H

#include "basic.h"
#include "integer.h"
#include "error.h"

#define CIRC_LIST(name, type) \
    struct name { \
        int x_head; \
        int x_size; \
        int x_cap; \
        int x_sizeof; \
        type x_list[EMPTY_ARRAY_SIZE]; \
    }

#define CIRC_LIST_PUSH(obj, item) \
    { \
        (obj)->x_head = modulo_add((obj)->x_head, -1, (obj)->x_cap); \
        (obj)->x_list[(obj)->x_head] = (item); \
        (obj)->x_size = min_int((obj)->x_size + 1, (obj)->x_cap); \
    }

#define CIRC_LIST_SIZE(obj) \
    ((obj)->x_size)

#define CIRC_LIST_INDEX(obj, index) \
    modulo_add((obj)->x_head, \
               index_verify((index), (obj)->x_size, __FILE__, __LINE__), \
               (obj)->x_cap)

#define CIRC_LIST_ITEM(obj, index) \
    ((obj)->x_list[CIRC_LIST_INDEX((obj), (index))])

#define CIRC_LIST_RESET(obj) \
    { \
        (obj)->x_head = 0; \
        (obj)->x_size = 0; \
    }

#define CIRC_LIST_ALLOC(dest, list_type, size) \
    { \
        const int so = sizeof(list_type) + sizeof((dest)->x_list[0]) * (size); \
        (dest) = (list_type *) malloc(so); \
        check_malloc_return(dest); \
        memset((dest), 0, so); \
        (dest)->x_cap = size; \
        (dest)->x_sizeof = so; \
    }

#define CIRC_LIST_FREE(dest) \
    free(dest)

#endif /* ifndef CIRC_LIST_H */
