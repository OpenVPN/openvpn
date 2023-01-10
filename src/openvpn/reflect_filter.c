/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2022-2023 OpenVPN Inc <sales@openvpn.net>
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


#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <memory.h>

#include "crypto.h"
#include "reflect_filter.h"


bool
reflect_filter_rate_limit_check(struct initial_packet_rate_limit *irl)
{
    if (now > irl->last_period_reset + irl->period_length)
    {
        int64_t dropped = irl->curr_period_counter - irl->max_per_period;
        if (dropped > 0)
        {
            msg(D_TLS_DEBUG_LOW, "Dropped %" PRId64 " initial handshake packets"
                " due to --connect-freq-initial %" PRId64 " %d", dropped,
                irl->max_per_period, irl->period_length);

        }
        irl->last_period_reset = now;
        irl->curr_period_counter = 0;
        irl->warning_displayed = false;
    }

    irl->curr_period_counter++;

    bool over_limit = irl->curr_period_counter > irl->max_per_period;

    if (over_limit && !irl->warning_displayed)
    {
        msg(M_WARN, "Note: --connect-freq-initial %" PRId64 " %d rate limit "
            "exceeded, dropping initial handshake packets for the next %d "
            "seconds", irl->max_per_period, irl->period_length,
            (int)(irl->last_period_reset + irl->period_length - now));
        irl->warning_displayed = true;
    }
    return !over_limit;
}

void
reflect_filter_rate_limit_decrease(struct initial_packet_rate_limit *irl)
{
    if (irl->curr_period_counter > 0)
    {
        irl->curr_period_counter--;
    }
}


struct initial_packet_rate_limit *
initial_rate_limit_init(int max_per_period, int period_length)
{
    struct initial_packet_rate_limit *irl;


    ALLOC_OBJ(irl, struct initial_packet_rate_limit);

    irl->max_per_period = max_per_period;
    irl->period_length = period_length;
    irl->curr_period_counter = 0;
    irl->last_period_reset = 0;

    return irl;
}

void
initial_rate_limit_free(struct initial_packet_rate_limit *irl)
{
    free(irl);
}
