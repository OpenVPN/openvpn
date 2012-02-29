/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
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

#if P2MP_SERVER

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

struct schedule *schedule_init (void);
void schedule_free (struct schedule *s);
void schedule_remove_entry (struct schedule *s, struct schedule_entry *e);

#ifdef SCHEDULE_TEST
void schedule_test (void);
#endif

/* Private Functions */

/* is node already in tree? */
#define IN_TREE(e) ((e)->pri)

struct schedule_entry *schedule_find_least (struct schedule_entry *e);
void schedule_add_modify (struct schedule *s, struct schedule_entry *e);
void schedule_remove_node (struct schedule *s, struct schedule_entry *e);

/* Public inline functions */

/*
 * Add a struct schedule_entry (whose storage is managed by
 * caller) to the btree.  tv signifies the wakeup time for
 * a future event.  sigma is a time interval measured
 * in microseconds -- the event window being represented
 * starts at (tv - sigma) and ends at (tv + sigma).
 * Event signaling can occur anywere within this interval.
 * Making the interval larger makes the scheduler more efficient,
 * while making it smaller results in more precise scheduling.
 * The caller should treat the passed struct schedule_entry as
 * an opaque object.
 */
static inline void
schedule_add_entry (struct schedule *s,
		    struct schedule_entry *e,
		    const struct timeval *tv,
		    unsigned int sigma)
{
  if (!IN_TREE (e) || !sigma || !tv_within_sigma (tv, &e->tv, sigma))
    {
      e->tv = *tv;
      schedule_add_modify (s, e);
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
schedule_get_earliest_wakeup (struct schedule *s,
			      struct timeval *wakeup)
{
  struct schedule_entry *ret;

  /* cache result */
  if (!s->earliest_wakeup)
    s->earliest_wakeup = schedule_find_least (s->root);
  ret = s->earliest_wakeup;
  if (ret)
    *wakeup = ret->tv;

  return ret;
}

#endif
#endif
