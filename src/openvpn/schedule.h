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

#ifndef SCHEDULE_H
#define SCHEDULE_H

/*
 * This code implements an efficient scheduler using
 * a random treap binary tree.
 *
 * The scheduler is used by the server executive to
 * keep track of which instances need service at a
 * known time in the future.  Instances need to
 * schedule events for things such as sending
 * a ping or scheduling a TLS renegotiation.
 */

/* define to enable a special test mode */
/*#define SCHEDULE_TEST*/

#include "otime.h"
#include "error.h"

struct schedule_entry
{
    struct timeval tv;             /* wakeup time */
    unsigned int pri;              /* random treap priority */
    struct schedule_entry *parent; /* treap (btree) links */
    struct schedule_entry *lt;
    struct schedule_entry *gt;
};

struct schedule
{
    struct schedule_entry *earliest_wakeup; /* cached earliest wakeup */
    struct schedule_entry *root;            /* the root of the treap (btree) */
};

/* Public functions */

struct schedule *schedule_init(void);

void schedule_free(struct schedule *s);

void schedule_remove_entry(struct schedule *s, struct schedule_entry *e);

#ifdef SCHEDULE_TEST
void schedule_test(void);

#endif

/* Private Functions */

/* is node already in tree? */
#define IN_TREE(e) ((e)->pri)

struct schedule_entry *schedule_find_least(struct schedule_entry *e);

void schedule_add_modify(struct schedule *s, struct schedule_entry *e);

void schedule_remove_node(struct schedule *s, struct schedule_entry *e);

/* Public inline functions */

/**
 * Add a struct schedule_entry to the scheduler btree or
 * update an existing entry with a new wakeup time.
 *
 * @p sigma is only used when the entry is already present
 * in the schedule. If the originally scheduled time and the new
 * time are within @p sigma microseconds of each other then the
 * entry is not rescheduled and will occur at the original time.
 * When adding a new entry @p sigma will be ignored.
 *
 * @param s     scheduler tree
 * @param e     entry to add to the schedule
 * @param tv    wakeup time for the entry
 * @param sigma window size for the event in microseconds
 *
 * @note The caller should treat @p e as opaque data. Only
 * the scheduler functions should change the object. The
 * caller is expected to manage the memory for the object
 * and must only free it once it has been removed from the
 * schedule.
 */
static inline void
schedule_add_entry(struct schedule *s, struct schedule_entry *e, const struct timeval *tv,
                   unsigned int sigma)
{
    if (!IN_TREE(e) || !sigma || !tv_within_sigma(tv, &e->tv, sigma))
    {
        e->tv = *tv;
        schedule_add_modify(s, e);
        s->earliest_wakeup = NULL; /* invalidate cache */
    }
}

/*
 * Return the node with the earliest wakeup time.  If two
 * nodes have the exact same wakeup time, select based on
 * the random priority assigned to each node (the priority
 * is randomized every time an entry is re-added).
 */
static inline struct schedule_entry *
schedule_get_earliest_wakeup(struct schedule *s, struct timeval *wakeup)
{
    struct schedule_entry *ret;

    /* cache result */
    if (!s->earliest_wakeup)
    {
        s->earliest_wakeup = schedule_find_least(s->root);
    }
    ret = s->earliest_wakeup;
    if (ret)
    {
        *wakeup = ret->tv;
    }

    return ret;
}

#endif /* ifndef SCHEDULE_H */
