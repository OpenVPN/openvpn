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
#include "schedule.h"
#include "test_common.h"

static inline bool
tv_lt(const struct timeval *t1, const struct timeval *t2)
{
    if (t1->tv_sec < t2->tv_sec)
    {
        return true;
    }
    else if (t1->tv_sec > t2->tv_sec)
    {
        return false;
    }
    else
    {
        return t1->tv_usec < t2->tv_usec;
    }
}

static inline bool
tv_le(const struct timeval *t1, const struct timeval *t2)
{
    if (t1->tv_sec < t2->tv_sec)
    {
        return true;
    }
    else if (t1->tv_sec > t2->tv_sec)
    {
        return false;
    }
    else
    {
        return t1->tv_usec <= t2->tv_usec;
    }
}

static inline bool
tv_eq(const struct timeval *t1, const struct timeval *t2)
{
    return t1->tv_sec == t2->tv_sec && t1->tv_usec == t2->tv_usec;
}

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
schedule_debug_entry(const struct schedule_entry *e, int depth, int *count, struct timeval *least,
                     const struct timeval *min, const struct timeval *max)
{
    struct gc_arena gc = gc_new();
    int maxdepth = depth;
    if (e)
    {
        int d;

        assert_ptr_not_equal(e, e->lt);
        assert_ptr_not_equal(e, e->gt);
        assert_ptr_not_equal(e, e->parent);
        assert_true(!e->parent || e->parent != e->lt);
        assert_true(!e->parent || e->parent != e->gt);
        assert_true(!e->lt || e->lt != e->gt);

        if (e->lt)
        {
            assert_ptr_equal(e->lt->parent, e);
            assert_int_equal(schedule_entry_compare(e->lt, e), -1);
            assert_true(e->lt->pri >= e->pri);
        }

        if (e->gt)
        {
            assert_ptr_equal(e->gt->parent, e);
            assert_int_equal(schedule_entry_compare(e->gt, e), 1);
            assert_true(e->gt->pri >= e->pri);
        }

        assert_true(tv_le(min, &e->tv));
        assert_true(tv_le(&e->tv, max));

        if (count)
        {
            ++(*count);
        }

        if (least && tv_lt(&e->tv, least))
        {
            *least = e->tv;
        }

        d = schedule_debug_entry(e->lt, depth + 1, count, least, min, &e->tv);
        if (d > maxdepth)
        {
            maxdepth = d;
        }

        d = schedule_debug_entry(e->gt, depth + 1, count, least, &e->tv, max);
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
        assert_null(s->root->parent);
    }
    return schedule_debug_entry(s->root, 0, count, least, &min, &max);
}

void
tv_randomize(struct timeval *tv)
{
    tv->tv_sec += random() % 100;
    tv->tv_usec = random() % 100;
}

void
schedule_verify(struct schedule *s, int n)
{
    struct gc_arena gc = gc_new();
    struct timeval least;

    least.tv_sec = least.tv_usec = 0x7FFFFFFF;

    int count = 0;
    int maxlev = schedule_debug(s, &count, &least);

    /* a stupid algorithm to do C23 stdc_bit_ceil_ui/stdc_bit_width
     * calculate roundup(log2 n) */
    int bit_ceil_n = 1;
    int log2n = 0;
    while (bit_ceil_n < n)
    {
        bit_ceil_n <<= 1;
        log2n++;
    }

    /* Since this is a binary tree the maximum level needs to be at least
     * log2(n) */
    assert_true(maxlev >= log2n);
    struct schedule_entry *e = schedule_find_earliest_wakeup(s);

    if (e)
    {
        assert_true(tv_eq(&least, &e->tv));
    }

    gc_free(&gc);
}

void
schedule_randomize_array(struct schedule_entry **array, int size)
{
    int i;
    for (i = 0; i < size; ++i)
    {
        const int src = rand() % size;
        struct schedule_entry *tmp = array[i];
        if (i != src)
        {
            array[i] = array[src];
            array[src] = tmp;
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
               tv_string(&e->tv, &gc), e->pri, (ptr_type)e, (ptr_type)e->parent, (ptr_type)e->lt,
               (ptr_type)e->gt);
        schedule_print_work(e->lt, indent + 1);
        schedule_print_work(e->gt, indent + 1);
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
schedule_test(void **state)
{
    struct gc_arena gc = gc_new();
    int n = 1000;
    int n_mod = 25;

    int i, j;
    struct schedule_entry **array;
    struct schedule *s = schedule_init();
    struct schedule_entry *e;

    ALLOC_ARRAY(array, struct schedule_entry *, n);

    for (i = 0; i < n; ++i)
    {
        ALLOC_OBJ_CLEAR(array[i], struct schedule_entry);
        tv_randomize(&array[i]->tv);
        /*schedule_print (s);*/
        /*schedule_verify (s, n);*/
        schedule_add_modify(s, array[i]);
    }

    schedule_randomize_array(array, n);

    /*schedule_print (s);*/
    schedule_verify(s, n);

    for (j = 1; j <= n_mod; ++j)
    {
        /*printf("Modification Phase Pass %d\n", j);*/

        for (i = 0; i < n; ++i)
        {
            e = schedule_find_earliest_wakeup(s);
            /*printf ("BEFORE %s\n", tv_string (&e->tv, &gc));*/
            tv_randomize(&e->tv);
            /*printf ("AFTER %s\n", tv_string (&e->tv, &gc));*/
            schedule_add_modify(s, e);
            /*schedule_verify (s, n);*/
            /*schedule_print (s);*/
        }
        schedule_verify(s, n);
        /*schedule_print (s);*/
    }

    /*printf ("INS=%d\n", z.ins);*/

    while ((e = schedule_find_earliest_wakeup(s)))
    {
        schedule_remove_node(s, e);
        /*schedule_verify (s, n);*/
    }
    schedule_verify(s, 0);
    assert_null(s->root);

    for (i = 0; i < n; ++i)
    {
        free(array[i]);
    }
    free(array);
    schedule_free(s);
    gc_free(&gc);
}
