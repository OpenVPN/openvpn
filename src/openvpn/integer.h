/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

#ifndef INTEGER_H
#define INTEGER_H

#include "error.h"

#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : \
                   ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif

#ifndef ntohll
#define ntohll(x) ((1==ntohl(1)) ? (x) : \
                   ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

/*
 * min/max functions
 */
static inline unsigned int
max_uint(unsigned int x, unsigned int y)
{
    if (x > y)
    {
        return x;
    }
    else
    {
        return y;
    }
}

static inline unsigned int
min_uint(unsigned int x, unsigned int y)
{
    if (x < y)
    {
        return x;
    }
    else
    {
        return y;
    }
}

static inline int
max_int(int x, int y)
{
    if (x > y)
    {
        return x;
    }
    else
    {
        return y;
    }
}

static inline int
min_int(int x, int y)
{
    if (x < y)
    {
        return x;
    }
    else
    {
        return y;
    }
}

static inline int
constrain_int(int x, int min, int max)
{
    if (min > max)
    {
        return min;
    }
    if (x < min)
    {
        return min;
    }
    else if (x > max)
    {
        return max;
    }
    else
    {
        return x;
    }
}

/*
 * Functions used for circular buffer index arithmetic.
 */

/*
 * Return x - y on a circle of circumference mod by shortest path.
 *
 * 0 <= x < mod
 * 0 <= y < mod
 */
static inline int
modulo_subtract(int x, int y, int mod)
{
    const int d1 = x - y;
    const int d2 = (x > y ? -mod : mod) + d1;
    ASSERT(0 <= x && x < mod && 0 <= y && y < mod);
    return abs(d1) > abs(d2) ? d2 : d1;
}

/*
 * Return x + y on a circle of circumference mod.
 *
 * 0 <= x < mod
 * -mod <= y <= mod
 */
static inline int
modulo_add(int x, int y, int mod)
{
    int sum = x + y;
    ASSERT(0 <= x && x < mod && -mod <= y && y <= mod);
    if (sum >= mod)
    {
        sum -= mod;
    }
    if (sum < 0)
    {
        sum += mod;
    }
    return sum;
}

/*
 * Return the next largest power of 2
 * or u if u is a power of 2.
 */
static inline size_t
adjust_power_of_2(size_t u)
{
    size_t ret = 1;

    while (ret < u)
    {
        ret <<= 1;
        ASSERT(ret > 0);
    }

    return ret;
}

static inline int
index_verify(int index, int size, const char *file, int line)
{
    if (index < 0 || index >= size)
    {
        msg(M_FATAL, "Assertion Failed: Array index=%d out of bounds for array size=%d in %s:%d",
            index,
            size,
            file,
            line);
    }
    return index;
}

/**
 * Rounds down num to the nearest multiple of multiple
 */
static inline unsigned int
round_down_uint(unsigned int num, unsigned int multiple)
{
    return (num / multiple) * multiple;
}

#endif /* ifndef INTEGER_H */
