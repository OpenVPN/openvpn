/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
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

#include "buffer.h"
#include "misc.h"
#include "crypto.h"
#include "schedule.h"

#include "memdbg.h"

#ifdef SCHEDULE_TEST

struct status
{
    int sru;
    int ins;
    int coll;
    int lsteps;
};

static struct status z;

#endif

#ifdef ENABLE_DEBUG
static void
schedule_entry_debug_info(const char *caller, const struct schedule_entry *e)
{
    struct gc_arena gc = gc_new();
    if (e)
    {
        dmsg(D_SCHEDULER, "SCHEDULE: %s wakeup=[%s] pri=%u",
             caller,
             tv_string_abs(&e->tv, &gc),
             e->pri);
    }
    else
    {
        dmsg(D_SCHEDULER, "SCHEDULE: %s NULL",
             caller);
    }
    gc_free(&gc);
}
#endif

static inline void
schedule_set_pri(struct schedule_entry *e)
{
    e->pri = random();
    if (e->pri < 1)
    {
        e->pri = 1;
    }
}

/* This is the master key comparison routine.  A key is
 * simply a struct timeval containing the absolute time for
 * an event.  The unique treap priority (pri) is used to ensure
 * that keys do not collide.
 */
static inline int
schedule_entry_compare(const struct schedule_entry *e1,
                       const struct schedule_entry *e2)
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

#ifdef SCHEDULE_TEST
        ++z.sru;
#endif
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

#ifdef SCHEDULE_TEST
        ++z.ins;
#endif

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
#ifdef SCHEDULE_TEST
            ++z.coll;
#endif
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
        schedule_insert(s, e);   /* trivial insert into tree */
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
#ifdef SCHEDULE_TEST
            ++z.lsteps;
#endif
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

/*
 *  Debug functions below this point
 */

#ifdef SCHEDULE_TEST

static inline struct schedule_entry *
schedule_find_earliest_wakeup(struct schedule *s)
{
    return schedule_find_least(s->root);
}

/*
 * Recursively check that the treap (btree) is
 * internally consistent.
 */
int
schedule_debug_entry(const struct schedule_entry *e,
                     int depth,
                     int *count,
                     struct timeval *least,
                     const struct timeval *min,
                     const struct timeval *max)
{
    struct gc_arena gc = gc_new();
    int maxdepth = depth;
    if (e)
    {
        int d;

        ASSERT(e != e->lt);
        ASSERT(e != e->gt);
        ASSERT(e != e->parent);
        ASSERT(!e->parent || e->parent != e->lt);
        ASSERT(!e->parent || e->parent != e->gt);
        ASSERT(!e->lt || e->lt != e->gt);

        if (e->lt)
        {
            ASSERT(e->lt->parent == e);
            ASSERT(schedule_entry_compare(e->lt, e) == -1);
            ASSERT(e->lt->pri >= e->pri);
        }

        if (e->gt)
        {
            ASSERT(e->gt->parent == e);
            ASSERT(schedule_entry_compare(e->gt, e));
            ASSERT(e->gt->pri >= e->pri);
        }

        ASSERT(tv_le(min, &e->tv));
        ASSERT(tv_le(&e->tv, max));

        if (count)
        {
            ++(*count);
        }

        if (least && tv_lt(&e->tv, least))
        {
            *least = e->tv;
        }

        d = schedule_debug_entry(e->lt, depth+1, count, least, min, &e->tv);
        if (d > maxdepth)
        {
            maxdepth = d;
        }

        d = schedule_debug_entry(e->gt, depth+1, count, least, &e->tv, max);
        if (d > maxdepth)
        {
            maxdepth = d;
        }
    }
    gc_free(&gc);
    return maxdepth;
}

int
schedule_debug(struct schedule *s, int *count, struct timeval *least)
{
    struct timeval min;
    struct timeval max;

    min.tv_sec = 0;
    min.tv_usec = 0;
    max.tv_sec = 0x7FFFFFFF;
    max.tv_usec = 0x7FFFFFFF;

    if (s->root)
    {
        ASSERT(s->root->parent == NULL);
    }
    return schedule_debug_entry(s->root, 0, count, least, &min, &max);
}

#if 1

void
tv_randomize(struct timeval *tv)
{
    tv->tv_sec += random() % 100;
    tv->tv_usec = random() % 100;
}

#else  /* if 1 */

void
tv_randomize(struct timeval *tv)
{
    struct gc_arena gc = gc_new();
    long int choice = get_random();
    if ((choice & 0xFF) == 0)
    {
        tv->tv_usec += ((choice >> 8) & 0xFF);
    }
    else
    {
        prng_bytes((uint8_t *)tv, sizeof(struct timeval));
    }
    gc_free(&gc);
}

#endif /* if 1 */

void
schedule_verify(struct schedule *s)
{
    struct gc_arena gc = gc_new();
    struct timeval least;
    int count;
    int maxlev;
    struct schedule_entry *e;
    const struct status zz = z;

    least.tv_sec = least.tv_usec = 0x7FFFFFFF;

    count = 0;

    maxlev = schedule_debug(s, &count, &least);

    e = schedule_find_earliest_wakeup(s);

    if (e)
    {
        printf("Verification Phase  count=%d maxlev=%d sru=%d ins=%d coll=%d ls=%d l=%s",
               count,
               maxlev,
               zz.sru,
               zz.ins,
               zz.coll,
               zz.lsteps,
               tv_string(&e->tv, &gc));

        if (!tv_eq(&least, &e->tv))
        {
            printf(" [COMPUTED DIFFERENT MIN VALUES!]");
        }

        printf("\n");
    }

    CLEAR(z);
    gc_free(&gc);
}

void
schedule_randomize_array(struct schedule_entry **array, int size)
{
    int i;
    for (i = 0; i < size; ++i)
    {
        const int src = get_random() % size;
        struct schedule_entry *tmp = array [i];
        if (i != src)
        {
            array [i] = array [src];
            array [src] = tmp;
        }
    }
}

void
schedule_print_work(struct schedule_entry *e, int indent)
{
    struct gc_arena gc = gc_new();
    int i;
    for (i = 0; i < indent; ++i)
    {
        printf(" ");
    }
    if (e)
    {
        printf("%s [%u] e=" ptr_format ", p=" ptr_format " lt=" ptr_format " gt=" ptr_format "\n",
               tv_string(&e->tv, &gc),
               e->pri,
               (ptr_type)e,
               (ptr_type)e->parent,
               (ptr_type)e->lt,
               (ptr_type)e->gt);
        schedule_print_work(e->lt, indent+1);
        schedule_print_work(e->gt, indent+1);
    }
    else
    {
        printf("NULL\n");
    }
    gc_free(&gc);
}

void
schedule_print(struct schedule *s)
{
    printf("*************************\n");
    schedule_print_work(s->root, 0);
}

void
schedule_test(void)
{
    struct gc_arena gc = gc_new();
    int n = 1000;
    int n_mod = 25;

    int i, j;
    struct schedule_entry **array;
    struct schedule *s = schedule_init();
    struct schedule_entry *e;

    CLEAR(z);
    ALLOC_ARRAY(array, struct schedule_entry *, n);

    printf("Creation/Insertion Phase\n");

    for (i = 0; i < n; ++i)
    {
        ALLOC_OBJ_CLEAR(array[i], struct schedule_entry);
        tv_randomize(&array[i]->tv);
        /*schedule_print (s);*/
        /*schedule_verify (s);*/
        schedule_add_modify(s, array[i]);
    }

    schedule_randomize_array(array, n);

    /*schedule_print (s);*/
    schedule_verify(s);

    for (j = 1; j <= n_mod; ++j)
    {
        printf("Modification Phase Pass %d\n", j);

        for (i = 0; i < n; ++i)
        {
            e = schedule_find_earliest_wakeup(s);
            /*printf ("BEFORE %s\n", tv_string (&e->tv, &gc));*/
            tv_randomize(&e->tv);
            /*printf ("AFTER %s\n", tv_string (&e->tv, &gc));*/
            schedule_add_modify(s, e);
            /*schedule_verify (s);*/
            /*schedule_print (s);*/
        }
        schedule_verify(s);
        /*schedule_print (s);*/
    }

    /*printf ("INS=%d\n", z.ins);*/

    while ((e = schedule_find_earliest_wakeup(s)))
    {
        schedule_remove_node(s, e);
        /*schedule_verify (s);*/
    }
    schedule_verify(s);

    printf("S->ROOT is %s\n", s->root ? "NOT NULL" : "NULL");

    for (i = 0; i < n; ++i)
    {
        free(array[i]);
    }
    free(array);
    free(s);
    gc_free(&gc);
}

#endif /* ifdef SCHEDULE_TEST */
