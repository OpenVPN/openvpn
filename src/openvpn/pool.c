/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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

#include "pool.h"
#include "buffer.h"
#include "error.h"
#include "socket.h"
#include "otime.h"

#include "memdbg.h"

static void
ifconfig_pool_entry_free(struct ifconfig_pool_entry *ipe, bool hard)
{
    ipe->in_use = false;
    if (hard && ipe->common_name)
    {
        free(ipe->common_name);
        ipe->common_name = NULL;
    }
    if (hard)
    {
        ipe->last_release = 0;
    }
    else
    {
        ipe->last_release = now;
    }
}

static int
ifconfig_pool_find(struct ifconfig_pool *pool, const char *common_name)
{
    int i;
    time_t earliest_release = 0;
    int previous_usage = -1;
    int new_usage = -1;

    for (i = 0; i < pool->size; ++i)
    {
        struct ifconfig_pool_entry *ipe = &pool->list[i];
        if (!ipe->in_use)
        {
            /*
             * If duplicate_cn mode, take first available IP address
             */
            if (pool->duplicate_cn)
            {
                new_usage = i;
                break;
            }

            /*
             * Keep track of the unused IP address entry which
             * was released earliest.
             */
            if ((new_usage == -1 || ipe->last_release < earliest_release) && !ipe->fixed)
            {
                earliest_release = ipe->last_release;
                new_usage = i;
            }

            /*
             * Keep track of a possible allocation to us
             * from an earlier session.
             */
            if (previous_usage < 0
                && common_name
                && ipe->common_name
                && !strcmp(common_name, ipe->common_name))
            {
                previous_usage = i;
            }

        }
    }

    if (previous_usage >= 0)
    {
        return previous_usage;
    }

    if (new_usage >= 0)
    {
        return new_usage;
    }

    return -1;
}

/*
 * Verify start/end range
 */
bool
ifconfig_pool_verify_range(const int msglevel, const in_addr_t start, const in_addr_t end)
{
    struct gc_arena gc = gc_new();
    bool ret = true;

    if (start > end)
    {
        msg(msglevel, "--ifconfig-pool start IP [%s] is greater than end IP [%s]",
            print_in_addr_t(start, 0, &gc),
            print_in_addr_t(end, 0, &gc));
        ret = false;
    }
    if (end - start >= IFCONFIG_POOL_MAX)
    {
        msg(msglevel, "--ifconfig-pool address range is too large [%s -> %s].  Current maximum is %d addresses, as defined by IFCONFIG_POOL_MAX variable.",
            print_in_addr_t(start, 0, &gc),
            print_in_addr_t(end, 0, &gc),
            IFCONFIG_POOL_MAX);
        ret = false;
    }
    gc_free(&gc);
    return ret;
}

struct ifconfig_pool *
ifconfig_pool_init(const bool ipv4_pool, enum pool_type type, in_addr_t start,
                   in_addr_t end, const bool duplicate_cn,
                   const bool ipv6_pool, const struct in6_addr ipv6_base,
                   const int ipv6_netbits )
{
    struct gc_arena gc = gc_new();
    struct ifconfig_pool *pool = NULL;
    int pool_ipv4_size = -1, pool_ipv6_size = -1;

    ASSERT(start <= end && end - start < IFCONFIG_POOL_MAX);
    ALLOC_OBJ_CLEAR(pool, struct ifconfig_pool);

    pool->duplicate_cn = duplicate_cn;

    pool->ipv4.enabled = ipv4_pool;

    if (pool->ipv4.enabled)
    {
        pool->ipv4.type = type;
        switch (pool->ipv4.type)
        {
            case IFCONFIG_POOL_30NET:
                pool->ipv4.base = start & ~3;
                pool_ipv4_size = (((end | 3) + 1) - pool->ipv4.base) >> 2;
                break;

            case IFCONFIG_POOL_INDIV:
                pool->ipv4.base = start;
                pool_ipv4_size = end - start + 1;
                break;

            default:
                ASSERT(0);
        }

        if (pool_ipv4_size < 2)
        {
            msg(M_FATAL, "IPv4 pool size is too small (%d), must be at least 2",
                pool_ipv4_size);
        }

        msg(D_IFCONFIG_POOL, "IFCONFIG POOL IPv4: base=%s size=%d",
            print_in_addr_t(pool->ipv4.base, 0, &gc), pool_ipv4_size);

        pool->size = pool_ipv4_size;
    }

    /* IPv6 pools are always "INDIV" type */
    pool->ipv6.enabled = ipv6_pool;

    if (pool->ipv6.enabled)
    {
        /* the host portion of the address will always be contained in the last
         * 4 bytes, therefore we can just extract that and use it as base in
         * integer form
         */
        uint32_t base = (ipv6_base.s6_addr[12] << 24)
                        | (ipv6_base.s6_addr[13] << 16)
                        | (ipv6_base.s6_addr[14] << 8)
                        | ipv6_base.s6_addr[15];
        /* some bits of the last 4 bytes may still be part of the network
         * portion of the address, therefore we need to set them to 0
         */
        if ((128 - ipv6_netbits) < 32)
        {
            /* extract only the bits that are really part of the host portion of
             * the address.
             *
             * Example: if we have netbits=31, the first bit has to be zero'd,
             * the following operation first computes mask=0x3fffff and then
             * uses mask to extract the wanted bits from base
             */
            uint32_t mask = (1 << (128 - ipv6_netbits) ) - 1;
            base &= mask;
        }

        pool->ipv6.base = ipv6_base;

        /* if a pool starts at a base address that has all-zero in the
         * host part, that first IPv6 address must not be assigned to
         * clients because it is not usable (subnet anycast address).
         * Start with 1, then.
         *
         * NOTE: this will also (mis-)fire for something like
         *    ifconfig-ipv6-pool 2001:db8:0:1:1234::0/64
         * as we only check the rightmost 32 bits of the host part.  So be it.
         */
        if (base == 0)
        {
            msg(D_IFCONFIG_POOL, "IFCONFIG POOL IPv6: incrementing pool start "
                "to avoid ::0 assignment");
            base++;
            pool->ipv6.base.s6_addr[15]++;
        }

        pool_ipv6_size = ipv6_netbits >= 112
                          ? (1 << (128 - ipv6_netbits)) - base
                          : IFCONFIG_POOL_MAX;

        if (pool_ipv6_size < 2)
        {
            msg(M_FATAL, "IPv6 pool size is too small (%d), must be at least 2",
                pool_ipv6_size);
        }

        msg(D_IFCONFIG_POOL, "IFCONFIG POOL IPv6: base=%s size=%d netbits=%d",
            print_in6_addr(pool->ipv6.base, 0, &gc), pool_ipv6_size,
            ipv6_netbits);

        /* if there is no v4 pool, or the v6 pool is smaller, use
         * v6 pool size as "unified pool size"
         */
        if (pool->size <= 0 || pool_ipv6_size < pool->size)
        {
            pool->size = pool_ipv6_size;
        }
    }

    if (pool->ipv4.enabled && pool->ipv6.enabled)
    {
        if (pool_ipv4_size < pool_ipv6_size)
        {
            msg(M_INFO, "NOTE: IPv4 pool size is %d, IPv6 pool size is %d. "
                "IPv4 pool size limits the number of clients that can be "
                "served from the pool", pool_ipv4_size, pool_ipv6_size);
        }
        else if (pool_ipv4_size > pool_ipv6_size)
        {
            msg(M_WARN, "WARNING: IPv4 pool size is %d, IPv6 pool size is %d. "
                "IPv6 pool size limits the number of clients that can be "
                "served from the pool. This is likely a MISTAKE - please check "
                "your configuration", pool_ipv4_size, pool_ipv6_size);
        }
    }

    ASSERT(pool->size > 0);

    ALLOC_ARRAY_CLEAR(pool->list, struct ifconfig_pool_entry, pool->size);

    gc_free(&gc);
    return pool;
}

void
ifconfig_pool_free(struct ifconfig_pool *pool)
{
    if (pool)
    {
        int i;

        for (i = 0; i < pool->size; ++i)
        {
            ifconfig_pool_entry_free(&pool->list[i], true);
        }
        free(pool->list);
        free(pool);
    }
}

ifconfig_pool_handle
ifconfig_pool_acquire(struct ifconfig_pool *pool, in_addr_t *local, in_addr_t *remote, struct in6_addr *remote_ipv6, const char *common_name)
{
    int i;

    i = ifconfig_pool_find(pool, common_name);
    if (i >= 0)
    {
        struct ifconfig_pool_entry *ipe = &pool->list[i];
        ASSERT(!ipe->in_use);
        ifconfig_pool_entry_free(ipe, true);
        ipe->in_use = true;
        if (common_name)
        {
            ipe->common_name = string_alloc(common_name, NULL);
        }

        if (pool->ipv4.enabled && local && remote)
        {
            switch (pool->ipv4.type)
            {
                case IFCONFIG_POOL_30NET:
                {
                    in_addr_t b = pool->ipv4.base + (i << 2);
                    *local = b + 1;
                    *remote = b + 2;
                    break;
                }

                case IFCONFIG_POOL_INDIV:
                {
                    in_addr_t b = pool->ipv4.base + i;
                    *local = 0;
                    *remote = b;
                    break;
                }

                default:
                    ASSERT(0);
            }
        }

        /* IPv6 pools are always INDIV (--linear) */
        if (pool->ipv6.enabled && remote_ipv6)
        {
            *remote_ipv6 = add_in6_addr(pool->ipv6.base, i);
        }
    }
    return i;
}

bool
ifconfig_pool_release(struct ifconfig_pool *pool, ifconfig_pool_handle hand, const bool hard)
{
    bool ret = false;

    if (pool && hand >= 0 && hand < pool->size)
    {
        ifconfig_pool_entry_free(&pool->list[hand], hard);
        ret = true;
    }
    return ret;
}

/*
 * private access functions
 */

/* currently handling IPv4 logic only */
static ifconfig_pool_handle
ifconfig_pool_ip_base_to_handle(const struct ifconfig_pool *pool, const in_addr_t addr)
{
    ifconfig_pool_handle ret = -1;

    switch (pool->ipv4.type)
    {
        case IFCONFIG_POOL_30NET:
        {
            ret = (addr - pool->ipv4.base) >> 2;
            break;
        }

        case IFCONFIG_POOL_INDIV:
        {
            ret = (addr - pool->ipv4.base);
            break;
        }

        default:
            ASSERT(0);
    }

    if (ret < 0 || ret >= pool->size)
    {
        ret = -1;
    }

    return ret;
}

static ifconfig_pool_handle
ifconfig_pool_ipv6_base_to_handle(const struct ifconfig_pool *pool,
                                  const struct in6_addr *in_addr)
{
    ifconfig_pool_handle ret;
    uint32_t base, addr;

    /* IPv6 pool is always IFCONFIG_POOL_INDIV.
     *
     * We assume the offset can't be larger than 2^32-1, therefore we compute
     * the difference only among the last 4 bytes like if they were two 32bit
     * long integers. The rest of the address must match.
     */
    for (int i = 0; i < (12); i++)
    {
        if (pool->ipv6.base.s6_addr[i] != in_addr->s6_addr[i])
        {
            return -1;
        }
    }

    base = (pool->ipv6.base.s6_addr[12] << 24)
           | (pool->ipv6.base.s6_addr[13] << 16)
           | (pool->ipv6.base.s6_addr[14] << 8)
           | pool->ipv6.base.s6_addr[15];

    addr = (in_addr->s6_addr[12] << 24)
           | (in_addr->s6_addr[13] << 16)
           | (in_addr->s6_addr[14] << 8)
           | in_addr->s6_addr[15];

    ret = addr - base;
    if (ret < 0 || ret >= pool->size)
    {
        ret = -1;
    }

    return ret;
}

static in_addr_t
ifconfig_pool_handle_to_ip_base(const struct ifconfig_pool *pool, ifconfig_pool_handle hand)
{
    in_addr_t ret = 0;

    if (pool->ipv4.enabled && hand >= 0 && hand < pool->size)
    {
        switch (pool->ipv4.type)
        {
            case IFCONFIG_POOL_30NET:
            {
                ret = pool->ipv4.base + (hand << 2);
                break;
            }

            case IFCONFIG_POOL_INDIV:
            {
                ret = pool->ipv4.base + hand;
                break;
            }

            default:
                ASSERT(0);
        }
    }

    return ret;
}

static struct in6_addr
ifconfig_pool_handle_to_ipv6_base(const struct ifconfig_pool *pool, ifconfig_pool_handle hand)
{
    struct in6_addr ret = IN6ADDR_ANY_INIT;

    /* IPv6 pools are always INDIV (--linear) */
    if (pool->ipv6.enabled && hand >= 0 && hand < pool->size)
    {
        ret = add_in6_addr( pool->ipv6.base, hand );
    }
    return ret;
}

static void
ifconfig_pool_set(struct ifconfig_pool *pool, const char *cn,
                  ifconfig_pool_handle h, const bool fixed)
{
    struct ifconfig_pool_entry *e = &pool->list[h];
    ifconfig_pool_entry_free(e, true);
    e->in_use = false;
    e->common_name = string_alloc(cn, NULL);
    e->last_release = now;
    e->fixed = fixed;
}

static void
ifconfig_pool_list(const struct ifconfig_pool *pool, struct status_output *out)
{
    if (pool && out)
    {
        struct gc_arena gc = gc_new();
        int i;

        for (i = 0; i < pool->size; ++i)
        {
            const struct ifconfig_pool_entry *e = &pool->list[i];
            struct in6_addr ip6;
            in_addr_t ip;
            const char *ip6_str = "";
            const char *ip_str = "";

            if (e->common_name)
            {
                if (pool->ipv4.enabled)
                {
                    ip = ifconfig_pool_handle_to_ip_base(pool, i);
                    ip_str = print_in_addr_t(ip, 0, &gc);
                }

                if (pool->ipv6.enabled)
                {
                    ip6 = ifconfig_pool_handle_to_ipv6_base(pool, i);
                    ip6_str = print_in6_addr(ip6, 0, &gc);
                }

                status_printf(out, "%s,%s,%s", e->common_name, ip_str, ip6_str);
            }
        }
        gc_free(&gc);
    }
}

static void
ifconfig_pool_msg(const struct ifconfig_pool *pool, int msglevel)
{
    struct status_output *so = status_open(NULL, 0, msglevel, NULL, 0);
    ASSERT(so);
    status_printf(so, "IFCONFIG POOL LIST");
    ifconfig_pool_list(pool, so);
    status_close(so);
}

/*
 * Deal with reading/writing the ifconfig pool database to a file
 */

struct ifconfig_pool_persist *
ifconfig_pool_persist_init(const char *filename, int refresh_freq)
{
    struct ifconfig_pool_persist *ret;

    ASSERT(filename);

    ALLOC_OBJ_CLEAR(ret, struct ifconfig_pool_persist);
    if (refresh_freq > 0)
    {
        ret->fixed = false;
        ret->file = status_open(filename, refresh_freq, -1, NULL, STATUS_OUTPUT_READ|STATUS_OUTPUT_WRITE);
    }
    else
    {
        ret->fixed = true;
        ret->file = status_open(filename, 0, -1, NULL, STATUS_OUTPUT_READ);
    }
    return ret;
}

void
ifconfig_pool_persist_close(struct ifconfig_pool_persist *persist)
{
    if (persist)
    {
        if (persist->file)
        {
            status_close(persist->file);
        }
        free(persist);
    }
}

bool
ifconfig_pool_write_trigger(struct ifconfig_pool_persist *persist)
{
    if (persist->file)
    {
        return status_trigger(persist->file);
    }
    else
    {
        return false;
    }
}

void
ifconfig_pool_read(struct ifconfig_pool_persist *persist, struct ifconfig_pool *pool)
{
    const int buf_size = 128;

    update_time();

    if (persist && persist->file && pool)
    {
        struct gc_arena gc = gc_new();
        struct buffer in = alloc_buf_gc(256, &gc);
        char *cn_buf, *ip_buf, *ip6_buf;

        ALLOC_ARRAY_CLEAR_GC(cn_buf, char, buf_size, &gc);
        ALLOC_ARRAY_CLEAR_GC(ip_buf, char, buf_size, &gc);
        ALLOC_ARRAY_CLEAR_GC(ip6_buf, char, buf_size, &gc);

        while (true)
        {
            ASSERT(buf_init(&in, 0));
            if (!status_read(persist->file, &in))
            {
                break;
            }
            if (!BLEN(&in))
            {
                continue;
            }

            int c = *BSTR(&in);
            if (c == '#' || c == ';')
            {
                continue;
            }

            msg(M_INFO, "ifconfig_pool_read(), in='%s'", BSTR(&in));

            /* The expected format of a line is: "CN,IP4,IP6".
             *
             * IP4 or IP6 may be empty when respectively no v4 or v6 pool
             * was previously specified.
             *
             * This means that accepted strings can be:
             * - CN,IP4,IP6
             * - CN,IP4
             * - CN,,IP6
             */
            if (!buf_parse(&in, ',', cn_buf, buf_size)
                || !buf_parse(&in, ',', ip_buf, buf_size))
            {
                continue;
            }

            ifconfig_pool_handle h = -1, h6 = -1;

            if (strlen(ip_buf) > 0)
            {
                bool v4_ok = true;
                in_addr_t addr = getaddr(GETADDR_HOST_ORDER, ip_buf, 0, &v4_ok,
                                         NULL);

                if (!v4_ok)
                {
                    msg(M_WARN, "pool: invalid IPv4 (%s) for CN=%s", ip_buf,
                        cn_buf);
                }
                else
                {
                    h = ifconfig_pool_ip_base_to_handle(pool, addr);
                    if (h < 0)
                    {
                        msg(M_WARN,
                            "pool: IPv4 (%s) out of pool range for CN=%s",
                            ip_buf, cn_buf);
                    }
                }
            }

            if (buf_parse(&in, ',', ip6_buf, buf_size) && strlen(ip6_buf) > 0)
            {
                struct in6_addr addr6;

                if (!get_ipv6_addr(ip6_buf, &addr6, NULL, M_WARN))
                {
                    msg(M_WARN, "pool: invalid IPv6 (%s) for CN=%s", ip6_buf,
                        cn_buf);
                }
                else
                {
                    h6 = ifconfig_pool_ipv6_base_to_handle(pool, &addr6);
                    if (h6 < 0)
                    {
                        msg(M_WARN,
                            "pool: IPv6 (%s) out of pool range for CN=%s",
                            ip6_buf, cn_buf);
                    }

                    /* Rely on IPv6 if no IPv4 was provided or the one provided
                     * was not valid
                     */
                    if (h < 0)
                    {
                        h = h6;
                    }
                }
            }

            /* at the moment IPv4 and IPv6 share the same pool, therefore offsets
             * have to match for the same client.
             *
             * If offsets differ we use the IPv4, therefore warn the user about this.
             */
            if ((h6 >= 0) && (h != h6))
            {
                msg(M_WARN,
                    "pool: IPv4 (%s) and IPv6 (%s) have different offsets! Relying on IPv4",
                    ip_buf, ip6_buf);
            }

            /* if at least one among v4 and v6 was properly parsed, attempt
             * setting an handle for this client
             */
            if (h >= 0)
            {
                msg(M_INFO, "succeeded -> ifconfig_pool_set(hand=%d)", h);
                ifconfig_pool_set(pool, cn_buf, h, persist->fixed);
            }
        }

        ifconfig_pool_msg(pool, D_IFCONFIG_POOL);

        gc_free(&gc);
    }
}

void
ifconfig_pool_write(struct ifconfig_pool_persist *persist, const struct ifconfig_pool *pool)
{
    if (persist && persist->file && (status_rw_flags(persist->file) & STATUS_OUTPUT_WRITE) && pool)
    {
        status_reset(persist->file);
        ifconfig_pool_list(pool, persist->file);
        status_flush(persist->file);
    }
}

/*
 * TESTING ONLY
 */

#ifdef IFCONFIG_POOL_TEST

#define DUP_CN

void
ifconfig_pool_test(in_addr_t start, in_addr_t end)
{
    struct gc_arena gc = gc_new();
    struct ifconfig_pool *p = ifconfig_pool_init(IFCONFIG_POOL_30NET, start, end);
    /*struct ifconfig_pool *p = ifconfig_pool_init (IFCONFIG_POOL_INDIV, start, end);*/
    ifconfig_pool_handle array[256];
    int i;

    CLEAR(array);

    msg(M_INFO | M_NOPREFIX, "************ 1");
    for (i = 0; i < (int) SIZE(array); ++i)
    {
        char *cn;
        ifconfig_pool_handle h;
        in_addr_t local, remote;
        char buf[256];
        snprintf(buf, sizeof(buf), "common-name-%d", i);
#ifdef DUP_CN
        cn = NULL;
#else
        cn = buf;
#endif
        h = ifconfig_pool_acquire(p, &local, &remote, NULL, cn);
        if (h < 0)
        {
            break;
        }
        msg(M_INFO | M_NOPREFIX, "IFCONFIG_POOL TEST pass 1: l=%s r=%s cn=%s",
            print_in_addr_t(local, 0, &gc),
            print_in_addr_t(remote, 0, &gc),
            cn);
        array[i] = h;

    }

    msg(M_INFO | M_NOPREFIX, "************* 2");
    for (i = (int) SIZE(array) / 16; i < (int) SIZE(array) / 8; ++i)
    {
        msg(M_INFO, "Attempt to release %d cn=%s", array[i], p->list[i].common_name);
        if (!ifconfig_pool_release(p, array[i]))
        {
            break;
        }
        msg(M_INFO, "Succeeded");
    }

    CLEAR(array);

    msg(M_INFO | M_NOPREFIX, "**************** 3");
    for (i = 0; i < (int) SIZE(array); ++i)
    {
        char *cn;
        ifconfig_pool_handle h;
        in_addr_t local, remote;
        char buf[256];
        snprintf(buf, sizeof(buf), "common-name-%d", i+24);
#ifdef DUP_CN
        cn = NULL;
#else
        cn = buf;
#endif
        h = ifconfig_pool_acquire(p, &local, &remote, NULL, cn);
        if (h < 0)
        {
            break;
        }
        msg(M_INFO | M_NOPREFIX, "IFCONFIG_POOL TEST pass 3: l=%s r=%s cn=%s",
            print_in_addr_t(local, 0, &gc),
            print_in_addr_t(remote, 0, &gc),
            cn);
        array[i] = h;

    }

    ifconfig_pool_free(p);
    gc_free(&gc);
}

#endif /* ifdef IFCONFIG_POOL_TEST */
