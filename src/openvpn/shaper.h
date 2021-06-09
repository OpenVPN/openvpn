/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
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

#ifndef SHAPER_H
#define SHAPER_H

/*#define SHAPER_DEBUG*/

#include "basic.h"
#include "integer.h"
#include "misc.h"
#include "error.h"
#include "interval.h"

/*
 * A simple traffic shaper for
 * the output direction.
 */

#define SHAPER_MIN 100          /* bytes per second */
#define SHAPER_MAX 100000000

#define SHAPER_MAX_TIMEOUT 10   /* seconds */

#define SHAPER_USE_FP

struct shaper
{
    int bytes_per_second;
    struct timeval wakeup;

#ifdef SHAPER_USE_FP
    double factor;
#else
    int factor;
#endif
};

void shaper_msg(struct shaper *s);

void shaper_reset_wakeup(struct shaper *s);

/*
 * We want to wake up in delay microseconds.  If timeval is larger
 * than delay, set timeval to delay.
 */
bool shaper_soonest_event(struct timeval *tv, int delay);

/*
 * inline functions
 */

static inline void
shaper_reset(struct shaper *s, int bytes_per_second)
{
    s->bytes_per_second = constrain_int(bytes_per_second, SHAPER_MIN, SHAPER_MAX);

#ifdef SHAPER_USE_FP
    s->factor = 1000000.0 / (double)s->bytes_per_second;
#else
    s->factor = 1000000 / s->bytes_per_second;
#endif
}

static inline void
shaper_init(struct shaper *s, int bytes_per_second)
{
    shaper_reset(s, bytes_per_second);
    shaper_reset_wakeup(s);
}

static inline int
shaper_current_bandwidth(struct shaper *s)
{
    return s->bytes_per_second;
}

/*
 * Returns traffic shaping delay in microseconds relative to current
 * time, or 0 if no delay.
 */
static inline int
shaper_delay(struct shaper *s)
{
    struct timeval tv;
    int delay = 0;

    if (tv_defined(&s->wakeup))
    {
        ASSERT(!openvpn_gettimeofday(&tv, NULL));
        delay = tv_subtract(&s->wakeup, &tv, SHAPER_MAX_TIMEOUT);
#ifdef SHAPER_DEBUG
        dmsg(D_SHAPER_DEBUG, "SHAPER shaper_delay delay=%d", delay);
#endif
    }

    return delay > 0 ? delay : 0;
}


/*
 * We are about to send a datagram of nbytes bytes.
 *
 * Compute when we can send another datagram,
 * based on target throughput (s->bytes_per_second).
 */
static inline void
shaper_wrote_bytes(struct shaper *s, int nbytes)
{
    struct timeval tv;

    /* compute delay in microseconds */
    tv.tv_sec = 0;
#ifdef SHAPER_USE_FP
    tv.tv_usec = min_int((int)((double)max_int(nbytes, 100) * s->factor), (SHAPER_MAX_TIMEOUT*1000000));
#else
    tv.tv_usec = s->bytes_per_second
                 ? min_int(max_int(nbytes, 100) * s->factor, (SHAPER_MAX_TIMEOUT*1000000))
                 : 0;
#endif

    if (tv.tv_usec)
    {
        ASSERT(!openvpn_gettimeofday(&s->wakeup, NULL));
        tv_add(&s->wakeup, &tv);

#ifdef SHAPER_DEBUG
        dmsg(D_SHAPER_DEBUG, "SHAPER shaper_wrote_bytes bytes=%d delay=%ld sec=%" PRIi64 " usec=%ld",
             nbytes,
             (long)tv.tv_usec,
             (int64_t)s->wakeup.tv_sec,
             (long)s->wakeup.tv_usec);
#endif
    }
}

#if 0
/*
 * Increase/Decrease bandwidth by a percentage.
 *
 * Return true if bandwidth changed.
 */
static inline bool
shaper_change_pct(struct shaper *s, int pct)
{
    const int orig_bandwidth = s->bytes_per_second;
    const int new_bandwidth = orig_bandwidth + (orig_bandwidth * pct / 100);
    ASSERT(s->bytes_per_second);
    shaper_reset(s, new_bandwidth);
    return s->bytes_per_second != orig_bandwidth;
}
#endif

#endif /* ifndef SHAPER_H */
