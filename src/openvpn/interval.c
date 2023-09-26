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
#endif

#include "syshead.h"

#include "interval.h"

#include "memdbg.h"

void
interval_init(struct interval *top, int horizon, int refresh)
{
    CLEAR(*top);
    top->refresh = refresh;
    top->horizon = horizon;
}

bool
event_timeout_trigger(struct event_timeout *et,
                      struct timeval *tv,
                      const int et_const_retry)
{
    if (!et->defined)
    {
        return false;
    }

    bool ret = false;
    time_t wakeup = event_timeout_remaining(et);

    if (wakeup <= 0)
    {
#if INTERVAL_DEBUG
        dmsg(D_INTERVAL, "EVENT event_timeout_trigger (%d) etcr=%d", et->n,
             et_const_retry);
#endif
        if (et_const_retry < 0)
        {
            et->last = now;
            wakeup = et->n;
            ret = true;
        }
        else
        {
            wakeup = et_const_retry;
        }
    }

    if (tv && wakeup < tv->tv_sec)
    {
#if INTERVAL_DEBUG
        dmsg(D_INTERVAL, "EVENT event_timeout_wakeup (%d/%d) etcr=%d",
             (int) wakeup, et->n, et_const_retry);
#endif
        tv->tv_sec = wakeup;
        tv->tv_usec = 0;
    }
    return ret;
}
