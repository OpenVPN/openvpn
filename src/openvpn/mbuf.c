/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if P2MP

#include "buffer.h"
#include "error.h"
#include "integer.h"
#include "misc.h"
#include "mbuf.h"

#include "memdbg.h"

struct mbuf_set *
mbuf_init(unsigned int size)
{
    struct mbuf_set *ret;
    ALLOC_OBJ_CLEAR(ret, struct mbuf_set);
    ret->capacity = adjust_power_of_2(size);
    ALLOC_ARRAY(ret->array, struct mbuf_item, ret->capacity);
    return ret;
}

void
mbuf_free(struct mbuf_set *ms)
{
    if (ms)
    {
        int i;
        for (i = 0; i < (int) ms->len; ++i)
        {
            struct mbuf_item *item = &ms->array[MBUF_INDEX(ms->head, i, ms->capacity)];
            mbuf_free_buf(item->buffer);
        }
        free(ms->array);
        free(ms);
    }
}

struct mbuf_buffer *
mbuf_alloc_buf(const struct buffer *buf)
{
    struct mbuf_buffer *ret;
    ALLOC_OBJ(ret, struct mbuf_buffer);
    ret->buf = clone_buf(buf);
    ret->refcount = 1;
    ret->flags = 0;
    return ret;
}

void
mbuf_free_buf(struct mbuf_buffer *mb)
{
    if (mb)
    {
        if (--mb->refcount <= 0)
        {
            free_buf(&mb->buf);
            free(mb);
        }
    }
}

void
mbuf_add_item(struct mbuf_set *ms, const struct mbuf_item *item)
{
    ASSERT(ms);
    if (ms->len == ms->capacity)
    {
        struct mbuf_item rm;
        ASSERT(mbuf_extract_item(ms, &rm));
        mbuf_free_buf(rm.buffer);
        msg(D_MULTI_DROPPED, "MBUF: mbuf packet dropped");
    }

    ASSERT(ms->len < ms->capacity);

    ms->array[MBUF_INDEX(ms->head, ms->len, ms->capacity)] = *item;
    if (++ms->len > ms->max_queued)
    {
        ms->max_queued = ms->len;
    }
    ++item->buffer->refcount;
}

bool
mbuf_extract_item(struct mbuf_set *ms, struct mbuf_item *item)
{
    bool ret = false;
    if (ms)
    {
        while (ms->len)
        {
            *item = ms->array[ms->head];
            ms->head = MBUF_INDEX(ms->head, 1, ms->capacity);
            --ms->len;
            if (item->instance) /* ignore dereferenced instances */
            {
                ret = true;
                break;
            }
        }
    }
    return ret;
}

struct multi_instance *
mbuf_peek_dowork(struct mbuf_set *ms)
{
    struct multi_instance *ret = NULL;
    if (ms)
    {
        int i;
        for (i = 0; i < (int) ms->len; ++i)
        {
            struct mbuf_item *item = &ms->array[MBUF_INDEX(ms->head, i, ms->capacity)];
            if (item->instance)
            {
                ret = item->instance;
                break;
            }
        }
    }
    return ret;
}

void
mbuf_dereference_instance(struct mbuf_set *ms, struct multi_instance *mi)
{
    if (ms)
    {
        int i;
        for (i = 0; i < (int) ms->len; ++i)
        {
            struct mbuf_item *item = &ms->array[MBUF_INDEX(ms->head, i, ms->capacity)];
            if (item->instance == mi)
            {
                mbuf_free_buf(item->buffer);
                item->buffer = NULL;
                item->instance = NULL;
                msg(D_MBUF, "MBUF: dereferenced queued packet");
            }
        }
    }
}

#else  /* if P2MP */
static void
dummy(void)
{
}
#endif /* P2MP */
