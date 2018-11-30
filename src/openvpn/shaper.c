/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
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
#include "shaper.h"
#include "memdbg.h"

#ifdef ENABLE_FEATURE_SHAPER

/*
 * We want to wake up in delay microseconds.  If timeval is larger
 * than delay, set timeval to delay.
 */
bool
shaper_soonest_event(struct timeval *tv, int delay)
{
    bool ret = false;
    if (delay < 1000000)
    {
        if (tv->tv_sec)
        {
            tv->tv_sec = 0;
            tv->tv_usec = delay;
            ret = true;
        }
        else if (delay < tv->tv_usec)
        {
            tv->tv_usec = delay;
            ret = true;
        }
    }
    else
    {
        const int sec = delay / 1000000;
        const int usec = delay % 1000000;

        if (sec < tv->tv_sec)
        {
            tv->tv_sec = sec;
            tv->tv_usec = usec;
            ret = true;
        }
        else if (sec == tv->tv_sec)
        {
            if (usec < tv->tv_usec)
            {
                tv->tv_usec = usec;
                ret = true;
            }
        }
    }
#ifdef SHAPER_DEBUG
    dmsg(D_SHAPER_DEBUG, "SHAPER shaper_soonest_event sec=%" PRIi64 " usec=%ld ret=%d",
         (int64_t)tv->tv_sec, (long)tv->tv_usec, (int)ret);
#endif
    return ret;
}

void
shaper_reset_wakeup(struct shaper *s)
{
    CLEAR(s->wakeup);
}

void
shaper_msg(struct shaper *s)
{
    msg(M_INFO, "Output Traffic Shaping initialized at %d bytes per second",
        s->bytes_per_second);
}

#else  /* ifdef ENABLE_FEATURE_SHAPER */
static void
dummy(void)
{
}
#endif /* ENABLE_FEATURE_SHAPER */
