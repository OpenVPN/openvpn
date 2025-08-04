/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
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

#include "otime.h"

#include "memdbg.h"

time_t now = 0;            /* GLOBAL */

static time_t now_adj = 0; /* GLOBAL */
time_t now_usec = 0;       /* GLOBAL */

/*
 * Try to filter out time instability caused by the system
 * clock backtracking or jumping forward.
 */

void
update_now(const time_t system_time)
{
    /* threshold at which to dampen forward jumps */
    const int forward_threshold = 86400;
    /* backward jump must be >= this many seconds before we adjust */
    const int backward_trigger = 10;
    time_t real_time = system_time + now_adj;

    if (real_time > now)
    {
        const time_t overshoot = real_time - now - 1;
        if (overshoot > forward_threshold && now_adj >= overshoot)
        {
            now_adj -= overshoot;
            real_time -= overshoot;
        }
        now = real_time;
    }
    else if (real_time < now - backward_trigger)
    {
        now_adj += (now - real_time);
    }
}

void
update_now_usec(struct timeval *tv)
{
    const time_t last = now;
    update_now(tv->tv_sec);
    if (now > last || (now == last && tv->tv_usec > now_usec))
    {
        now_usec = tv->tv_usec;
    }
}

/*
 * Return a numerical string describing a struct timeval.
 */
const char *
tv_string(const struct timeval *tv, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(64, gc);
    buf_printf(&out, "[%" PRIi64 "/%ld]",
               (int64_t)tv->tv_sec,
               (long)tv->tv_usec);
    return BSTR(&out);
}

/*
 * Return an ascii string describing an absolute
 * date/time in a struct timeval.
 *
 */
const char *
tv_string_abs(const struct timeval *tv, struct gc_arena *gc)
{
    return time_string((time_t) tv->tv_sec,
                       (long) tv->tv_usec,
                       true,
                       gc);
}

/* format a time_t as ascii, or use current time if 0 */

const char *
time_string(time_t t, long usec, bool show_usec, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(64, gc);
    struct timeval tv;

    if (t)
    {
        tv.tv_sec = t;
        tv.tv_usec = usec;
    }
    else
    {
        gettimeofday(&tv, NULL);
    }

    t = tv.tv_sec;
    struct tm *tm = localtime(&t);

    buf_printf(&out, "%04d-%02d-%02d %02d:%02d:%02d",
               tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
               tm->tm_hour, tm->tm_min, tm->tm_sec);

    if (show_usec && tv.tv_usec)
    {
        buf_printf(&out, " us=%ld", (long)tv.tv_usec);
    }

    return BSTR(&out);
}

/*
 * Limit the frequency of an event stream.
 *
 * Used to control maximum rate of new
 * incoming connections.
 */

struct frequency_limit *
frequency_limit_init(int max, int per)
{
    struct frequency_limit *f;

    ASSERT(max >= 0 && per >= 0);

    ALLOC_OBJ(f, struct frequency_limit);
    f->max = max;
    f->per = per;
    f->n = 0;
    f->reset = 0;
    return f;
}

void
frequency_limit_free(struct frequency_limit *f)
{
    free(f);
}

bool
frequency_limit_event_allowed(struct frequency_limit *f)
{
    if (f->per)
    {
        bool ret;
        if (now >= f->reset + f->per)
        {
            f->reset = now;
            f->n = 0;
        }
        ret = (++f->n <= f->max);
        return ret;
    }
    else
    {
        return true;
    }
}

#ifdef TIME_TEST
void
time_test(void)
{
    struct timeval tv;
    time_t t;
    int i;
    for (i = 0; i < 10000; ++i)
    {
        t = time(NULL);
        gettimeofday(&tv, NULL);
#if 1
        msg(M_INFO, "t=%" PRIi64 " s=%" PRIi64 " us=%ld",
            (int64_t)t,
            (int64_t)tv.tv_sec,
            (long)tv.tv_usec);
#endif
    }
}
#endif
