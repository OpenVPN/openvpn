/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "buffer.h"
#include "misc.h"
#include "crypto.h"
#include "schedule.h"

#include "memdbg.h"

#ifdef ENABLE_DEBUG
static void
schedule_entry_debug_info(const char *caller, const struct schedule_entry *e)
{
    struct gc_arena gc = gc_new();
    if (e)
    {
        dmsg(D_SCHEDULER, "SCHEDULE: %s wakeup=[%s] pri=%u", caller, tv_string_abs(&e->tv, &gc),
             e->pri);
    }
    else
    {
        dmsg(D_SCHEDULER, "SCHEDULE: %s NULL", caller);
    }
    gc_free(&gc);
}
#endif

static inline void
schedule_set_pri(struct schedule_entry *e)
{
    e->pri = (unsigned int)random();
    if (e->pri < 1)
    {
        e->pri = 1;
    }
}

int
schedule_entry_compare(const struct schedule_entry *e1, const struct schedule_entry *e2)
{
    if (e1->tv.tv_sec < e2->tv.tv_sec)
    {
        return -1;
    }
    else if (e1->tv.tv_sec > e2->tv.tv_sec)
    {
        return 1;
    }
    else
    {
        if (e1->tv.tv_usec < e2->tv.tv_usec)
        {
            return -1;
        }
        else if (e1->tv.tv_usec > e2->tv.tv_usec)
        {
            return 1;
        }
        else
        {
            if (e1->pri < e2->pri)
            {
                return -1;
            }
            else if (e1->pri > e2->pri)
            {
                return 1;
            }
            else
            {
                return 0;
            }
        }
    }
}

/*
 * Detach a btree node from its parent
 */
static inline void
schedule_detach_parent(struct schedule *s, struct schedule_entry *e)
{
    if (e)
    {
        if (e->parent)
        {
            if (e->parent->lt == e)
            {
                e->parent->lt = NULL;
            }
            else if (e->parent->gt == e)
            {
                e->parent->gt = NULL;
            }
            else
            {
                /* parent <-> child linkage is corrupted */
                ASSERT(0);
            }
            e->parent = NULL;
        }
        else
        {
            if (s->root == e) /* last element deleted, tree is empty */
            {
                s->root = NULL;
            }
        }
    }
}

/*
 *
 * Given a binary search tree, move a node toward the root
 * while still maintaining the correct ordering relationships
 * within the tree.  This function is the workhorse
 * of the tree balancer.
 *
 * This code will break on key collisions, which shouldn't
 * happen because the treap priority is considered part of the key
 * and is guaranteed to be unique.
 */
static void
schedule_rotate_up(struct schedule *s, struct schedule_entry *e)
{
    if (e && e->parent)
    {
        struct schedule_entry *lt = e->lt;
        struct schedule_entry *gt = e->gt;
        struct schedule_entry *p = e->parent;
        struct schedule_entry *gp = p->parent;

        if (gp) /* if grandparent exists, modify its child link */
        {
            if (gp->gt == p)
            {
                gp->gt = e;
            }
            else if (gp->lt == p)
            {
                gp->lt = e;
            }
            else
            {
                ASSERT(0);
            }
        }
        else /* no grandparent, now we are the root */
        {
            s->root = e;
        }

        /* grandparent is now our parent */
        e->parent = gp;

        /* parent is now our child */
        p->parent = e;

        /* reorient former parent's links
         * to reflect new position in the tree */
        if (p->gt == e)
        {
            e->lt = p;
            p->gt = lt;
            if (lt)
            {
                lt->parent = p;
            }
        }
        else if (p->lt == e)
        {
            e->gt = p;
            p->lt = gt;
            if (gt)
            {
                gt->parent = p;
            }
        }
        else
        {
            /* parent <-> child linkage is corrupted */
            ASSERT(0);
        }
    }
}

/*
 * This is the treap deletion algorithm:
 *
 * Rotate lesser-priority children up in the tree
 * until we are childless.  Then delete.
 */
void
schedule_remove_node(struct schedule *s, struct schedule_entry *e)
{
    while (e->lt || e->gt)
    {
        if (e->lt)
        {
            if (e->gt)
            {
                if (e->lt->pri < e->gt->pri)
                {
                    schedule_rotate_up(s, e->lt);
                }
                else
                {
                    schedule_rotate_up(s, e->gt);
                }
            }
            else
            {
                schedule_rotate_up(s, e->lt);
            }
        }
        else if (e->gt)
        {
            schedule_rotate_up(s, e->gt);
        }
    }

    schedule_detach_parent(s, e);
    e->pri = 0;
}

/*
 * Trivially add a node to a binary search tree without
 * regard for balance.
 */
static void
schedule_insert(struct schedule *s, struct schedule_entry *e)
{
    struct schedule_entry *c = s->root;
    while (true)
    {
        const int comp = schedule_entry_compare(e, c);

        if (comp == -1)
        {
            if (c->lt)
            {
                c = c->lt;
                continue;
            }
            else
            {
                c->lt = e;
                e->parent = c;
                break;
            }
        }
        else if (comp == 1)
        {
            if (c->gt)
            {
                c = c->gt;
                continue;
            }
            else
            {
                c->gt = e;
                e->parent = c;
                break;
            }
        }
        else
        {
            /* rare key/priority collision -- no big deal,
             * just choose another priority and retry */
            schedule_set_pri(e);
            /* msg (M_INFO, "PRI COLLISION pri=%u", e->pri); */
            c = s->root;
            continue;
        }
    }
}

/*
 * Given an element, remove it from the btree if it's already
 * there and re-insert it based on its current key.
 */
void
schedule_add_modify(struct schedule *s, struct schedule_entry *e)
{
#ifdef ENABLE_DEBUG
    if (check_debug_level(D_SCHEDULER))
    {
        schedule_entry_debug_info("schedule_add_modify", e);
    }
#endif

    /* already in tree, remove */
    if (IN_TREE(e))
    {
        schedule_remove_node(s, e);
    }

    /* set random priority */
    schedule_set_pri(e);

    if (s->root)
    {
        schedule_insert(s, e); /* trivial insert into tree */
    }
    else
    {
        s->root = e; /* tree was empty, we are the first element */
    }
    /* This is the magic of the randomized treap algorithm which
     * keeps the tree balanced.  Move the node up the tree until
     * its own priority is greater than that of its parent */
    while (e->parent && e->parent->pri > e->pri)
    {
        schedule_rotate_up(s, e);
    }
}

/*
 * Find the earliest event to be scheduled
 */
struct schedule_entry *
schedule_find_least(struct schedule_entry *e)
{
    if (e)
    {
        while (e->lt)
        {
            e = e->lt;
        }
    }

#ifdef ENABLE_DEBUG
    if (check_debug_level(D_SCHEDULER))
    {
        schedule_entry_debug_info("schedule_find_least", e);
    }
#endif

    return e;
}

/*
 *  Public functions below this point
 */

struct schedule *
schedule_init(void)
{
    struct schedule *s;

    ALLOC_OBJ_CLEAR(s, struct schedule);
    return s;
}

void
schedule_free(struct schedule *s)
{
    free(s);
}

void
schedule_remove_entry(struct schedule *s, struct schedule_entry *e)
{
    s->earliest_wakeup = NULL; /* invalidate cache */
    schedule_remove_node(s, e);
}