/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

#ifndef OTIME_H
#define OTIME_H

#include "common.h"
#include "integer.h"
#include "buffer.h"

struct frequency_limit
{
    int max;
    int per;
    int n;
    time_t reset;
};

struct frequency_limit *frequency_limit_init(int max, int per);

void frequency_limit_free(struct frequency_limit *f);

bool frequency_limit_event_allowed(struct frequency_limit *f);

/* format a time_t as ascii, or use current time if 0 */
const char *time_string(time_t t, int usec, bool show_usec, struct gc_arena *gc);

/* struct timeval functions */

const char *tv_string(const struct timeval *tv, struct gc_arena *gc);

const char *tv_string_abs(const struct timeval *tv, struct gc_arena *gc);

extern time_t now; /* updated frequently to time(NULL) */

void time_test(void);

void update_now(const time_t system_time);

extern time_t now_usec;
void update_now_usec(struct timeval *tv);

static inline int
openvpn_gettimeofday(struct timeval *tv, void *tz)
{
    const int status = gettimeofday(tv, tz);
    if (!status)
    {
        update_now_usec(tv);
        tv->tv_sec = now;
        tv->tv_usec = now_usec;
    }
    return status;
}

static inline void
update_time(void)
{
#ifdef _WIN32
    /* on _WIN32, gettimeofday is faster than time(NULL) */
    struct timeval tv;
    openvpn_gettimeofday(&tv, NULL);
#else
    update_now(time(NULL));
    now_usec = 0;
#endif
}

static inline time_t
openvpn_time(time_t *t)
{
    update_time();
    if (t)
    {
        *t = now;
    }
    return now;
}

static inline void
tv_clear(struct timeval *tv)
{
    tv->tv_sec = 0;
    tv->tv_usec = 0;
}

static inline bool
tv_defined(const struct timeval *tv)
{
    return tv->tv_sec > 0 && tv->tv_usec > 0;
}

/* return tv1 - tv2 in usec, constrained by max_seconds */
static inline int
tv_subtract(const struct timeval *tv1, const struct timeval *tv2, const unsigned int max_seconds)
{
    const int max_usec = max_seconds * 1000000;
    const int sec_diff = tv1->tv_sec - tv2->tv_sec;

    if (sec_diff > ((int)max_seconds + 10))
    {
        return max_usec;
    }
    else if (sec_diff < -((int)max_seconds + 10))
    {
        return -max_usec;
    }
    return constrain_int(sec_diff * 1000000 + (tv1->tv_usec - tv2->tv_usec), -max_usec, max_usec);
}

static inline void
tv_add(struct timeval *dest, const struct timeval *src)
{
    dest->tv_sec += src->tv_sec;
    dest->tv_usec += src->tv_usec;
    dest->tv_sec += (dest->tv_usec >> 20);
    dest->tv_usec &= 0x000FFFFF;
    if (dest->tv_usec >= 1000000)
    {
        dest->tv_usec -= 1000000;
        dest->tv_sec += 1;
    }
}

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
tv_ge(const struct timeval *t1, const struct timeval *t2)
{
    if (t1->tv_sec > t2->tv_sec)
    {
        return true;
    }
    else if (t1->tv_sec < t2->tv_sec)
    {
        return false;
    }
    else
    {
        return t1->tv_usec >= t2->tv_usec;
    }
}

static inline bool
tv_gt(const struct timeval *t1, const struct timeval *t2)
{
    if (t1->tv_sec > t2->tv_sec)
    {
        return true;
    }
    else if (t1->tv_sec < t2->tv_sec)
    {
        return false;
    }
    else
    {
        return t1->tv_usec > t2->tv_usec;
    }
}

static inline bool
tv_eq(const struct timeval *t1, const struct timeval *t2)
{
    return t1->tv_sec == t2->tv_sec && t1->tv_usec == t2->tv_usec;
}

static inline void
tv_delta(struct timeval *dest, const struct timeval *t1, const struct timeval *t2)
{
    int sec = t2->tv_sec - t1->tv_sec;
    int usec = t2->tv_usec - t1->tv_usec;

    while (usec < 0)
    {
        usec += 1000000;
        sec -= 1;
    }

    if (sec < 0)
    {
        usec = sec = 0;
    }

    dest->tv_sec = sec;
    dest->tv_usec = usec;
}

#define TV_WITHIN_SIGMA_MAX_SEC 600
#define TV_WITHIN_SIGMA_MAX_USEC (TV_WITHIN_SIGMA_MAX_SEC * 1000000)

/*
 * Is t1 and t2 within sigma microseconds of each other?
 */
static inline bool
tv_within_sigma(const struct timeval *t1, const struct timeval *t2, unsigned int sigma)
{
    const int delta = tv_subtract(t1, t2, TV_WITHIN_SIGMA_MAX_SEC); /* sigma should be less than 10 minutes */
    return -(int)sigma <= delta && delta <= (int)sigma;
}

/*
 * Used to determine in how many seconds we should be
 * called again.
 */
static inline void
interval_earliest_wakeup(interval_t *wakeup, time_t at, time_t current)
{
    if (at > current)
    {
        const interval_t delta = (interval_t) (at - current);
        if (delta < *wakeup)
        {
            *wakeup = delta;
        }
        if (*wakeup < 0)
        {
            *wakeup = 0;
        }
    }
}

#endif /* ifndef OTIME_H */
