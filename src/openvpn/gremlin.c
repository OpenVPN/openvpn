/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
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

/*
 * Test protocol robustness by simulating dropped packets and
 * network outages when the --gremlin option is used.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#ifdef ENABLE_DEBUG

#include "error.h"
#include "common.h"
#include "crypto.h"
#include "misc.h"
#include "otime.h"
#include "gremlin.h"

#include "memdbg.h"

/*
 * Parameters for packet corruption and droppage.
 * Each parameter has 4 possible levels, 0 = disabled,
 * while 1, 2, and 3 are enumerated in the below arrays.
 * The parameter is a 2-bit field within the --gremlin
 * parameter.
 */

/*
 * Probability that we will drop a packet is 1 / n
 */
static const int drop_freq[] = { 500, 100, 50 };

/*
 * Probability that we will corrupt a packet is 1 / n
 */
static const int corrupt_freq[] = { 500, 100, 50 };

/*
 * When network goes up, it will be up for between
 * UP_LOW and UP_HIGH seconds.
 */
static const int up_low[] =  {  60, 10,  5 };
static const int up_high[] = { 600, 60, 10 };

/*
 * When network goes down, it will be down for between
 * DOWN_LOW and DOWN_HIGH seconds.
 */
static const int down_low[] =  {  5, 10,  10 };
static const int down_high[] = { 10, 60, 120 };

/*
 * Packet flood levels:
 *  { number of packets, packet size }
 */
static const struct packet_flood_parms packet_flood_data[] =
{{10, 100}, {10, 1500}, {100, 1500}};

struct packet_flood_parms
get_packet_flood_parms(int level)
{
    ASSERT(level > 0 && level < 4);
    return packet_flood_data [level - 1];
}

/*
 * Return true with probability 1/n
 */
static bool
flip(int n)
{
    return (get_random() % n) == 0;
}

/*
 * Return uniformly distributed random number between
 * low and high.
 */
static int
roll(int low, int high)
{
    int ret;
    ASSERT(low <= high);
    ret = low + (get_random() % (high - low + 1));
    ASSERT(ret >= low && ret <= high);
    return ret;
}

static bool initialized; /* GLOBAL */
static bool up;          /* GLOBAL */
static time_t next;      /* GLOBAL */

/*
 * Return false if we should drop a packet.
 */
bool
ask_gremlin(int flags)
{
    const int up_down_level = GREMLIN_UP_DOWN_LEVEL(flags);
    const int drop_level = GREMLIN_DROP_LEVEL(flags);

    if (!initialized)
    {
        initialized = true;

        if (up_down_level)
        {
            up = false;
        }
        else
        {
            up = true;
        }

        next = now;
    }

    if (up_down_level) /* change up/down state? */
    {
        if (now >= next)
        {
            int delta;
            if (up)
            {
                delta = roll(down_low[up_down_level-1], down_high[up_down_level-1]);
                up = false;
            }
            else
            {
                delta = roll(up_low[up_down_level-1], up_high[up_down_level-1]);
                up = true;
            }

            msg(D_GREMLIN,
                "GREMLIN: CONNECTION GOING %s FOR %d SECONDS",
                (up ? "UP" : "DOWN"),
                delta);
            next = now + delta;
        }
    }

    if (drop_level)
    {
        if (up && flip(drop_freq[drop_level-1]))
        {
            dmsg(D_GREMLIN_VERBOSE, "GREMLIN: Random packet drop");
            return false;
        }
    }

    return up;
}

/*
 * Possibly corrupt a packet.
 */
void
corrupt_gremlin(struct buffer *buf, int flags)
{
    const int corrupt_level = GREMLIN_CORRUPT_LEVEL(flags);
    if (corrupt_level)
    {
        if (flip(corrupt_freq[corrupt_level-1]))
        {
            do
            {
                if (buf->len > 0)
                {
                    uint8_t r = roll(0, 255);
                    int method = roll(0, 5);

                    switch (method)
                    {
                        case 0: /* corrupt the first byte */
                            *BPTR(buf) = r;
                            break;

                        case 1: /* corrupt the last byte */
                            *(BPTR(buf) + buf->len - 1) = r;
                            break;

                        case 2: /* corrupt a random byte */
                            *(BPTR(buf) + roll(0, buf->len - 1)) = r;
                            break;

                        case 3: /* append a random byte */
                            buf_write(buf, &r, 1);
                            break;

                        case 4: /* reduce length by 1 */
                            --buf->len;
                            break;

                        case 5: /* reduce length by a random amount */
                            buf->len -= roll(0, buf->len - 1);
                            break;
                    }
                    dmsg(D_GREMLIN_VERBOSE, "GREMLIN: Packet Corruption, method=%d", method);
                }
                else
                {
                    break;
                }
            } while (flip(2));  /* a 50% chance we will corrupt again */
        }
    }
}

#else  /* ifdef ENABLE_DEBUG */
static void
dummy(void)
{
}
#endif /* ifdef ENABLE_DEBUG */
