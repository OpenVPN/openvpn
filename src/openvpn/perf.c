/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "perf.h"

#ifdef ENABLE_PERFORMANCE_METRICS

#include "error.h"
#include "otime.h"

#include "memdbg.h"

static const char *metric_names[] = {
    "PERF_BIO_READ_PLAINTEXT",
    "PERF_BIO_WRITE_PLAINTEXT",
    "PERF_BIO_READ_CIPHERTEXT",
    "PERF_BIO_WRITE_CIPHERTEXT",
    "PERF_TLS_MULTI_PROCESS",
    "PERF_IO_WAIT",
    "PERF_EVENT_LOOP",
    "PERF_MULTI_CREATE_INSTANCE",
    "PERF_MULTI_CLOSE_INSTANCE",
    "PERF_MULTI_SHOW_STATS",
    "PERF_MULTI_BCAST",
    "PERF_MULTI_MCAST",
    "PERF_SCRIPT",
    "PERF_READ_IN_LINK",
    "PERF_PROC_IN_LINK",
    "PERF_READ_IN_TUN",
    "PERF_PROC_IN_TUN",
    "PERF_PROC_OUT_LINK",
    "PERF_PROC_OUT_TUN",
    "PERF_PROC_OUT_TUN_MTCP"
};

struct perf
{
#define PS_INITIAL            0
#define PS_METER_RUNNING      1
#define PS_METER_INTERRUPTED  2
    int state;

    struct timeval start;
    double sofar;
    double sum;
    double max;
    double count;
};

struct perf_set
{
    int stack_len;
    int stack[STACK_N];
    struct perf perf[PERF_N];
};

static struct perf_set perf_set;

static void perf_print_state(int lev);

static inline int
get_stack_index(int sdelta)
{
    const int sindex = perf_set.stack_len + sdelta;
    if (sindex >= 0 && sindex < STACK_N)
    {
        return sindex;
    }
    else
    {
        return -1;
    }
}

static int
get_perf_index(int sdelta)
{
    const int sindex = get_stack_index(sdelta);
    if (sindex >= 0)
    {
        const int pindex = perf_set.stack[sindex];
        if (pindex >= 0 && pindex < PERF_N)
        {
            return pindex;
        }
        else
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }
}

static struct perf *
get_perf(int sdelta)
{
    const int pindex = get_perf_index(sdelta);
    if (pindex >= 0)
    {
        return &perf_set.perf[pindex];
    }
    else
    {
        return NULL;
    }
}

static void
push_perf_index(int pindex)
{
    const int sindex = get_stack_index(0);
    const int newlen = get_stack_index(1);
    if (sindex >= 0 && newlen >= 0
        && pindex >= 0 && pindex < PERF_N)
    {
        int i;
        for (i = 0; i < sindex; ++i)
        {
            if (perf_set.stack[i] == pindex)
            {
                perf_print_state(M_INFO);
                msg(M_FATAL, "PERF: push_perf_index %s failed",
                    metric_names [pindex]);
            }
        }

        perf_set.stack[sindex] = pindex;
        perf_set.stack_len = newlen;
    }
    else
    {
        msg(M_FATAL, "PERF: push_perf_index: stack push error");
    }
}

static void
pop_perf_index(void)
{
    const int newlen = get_stack_index(-1);
    if (newlen >= 0)
    {
        perf_set.stack_len = newlen;
    }
    else
    {
        msg(M_FATAL, "PERF: pop_perf_index: stack pop error");
    }
}

static void
state_must_be(const struct perf *p, const int wanted)
{
    if (p->state != wanted)
    {
        msg(M_FATAL, "PERF: bad state actual=%d wanted=%d",
            p->state,
            wanted);
    }
}

static void
update_sofar(struct perf *p)
{
    struct timeval current;
    ASSERT(!gettimeofday(&current, NULL));
    p->sofar += (double) tv_subtract(&current, &p->start, 600) / 1000000.0;
    tv_clear(&p->start);
}

static void
perf_start(struct perf *p)
{
    state_must_be(p, PS_INITIAL);
    ASSERT(!gettimeofday(&p->start, NULL));
    p->sofar = 0.0;
    p->state = PS_METER_RUNNING;
}

static void
perf_stop(struct perf *p)
{
    state_must_be(p, PS_METER_RUNNING);
    update_sofar(p);
    p->sum += p->sofar;
    if (p->sofar > p->max)
    {
        p->max = p->sofar;
    }
    p->count += 1.0;
    p->sofar = 0.0;
    p->state = PS_INITIAL;
}

static void
perf_interrupt(struct perf *p)
{
    state_must_be(p, PS_METER_RUNNING);
    update_sofar(p);
    p->state = PS_METER_INTERRUPTED;
}

static void
perf_resume(struct perf *p)
{
    state_must_be(p, PS_METER_INTERRUPTED);
    ASSERT(!gettimeofday(&p->start, NULL));
    p->state = PS_METER_RUNNING;
}

void
perf_push(int type)
{
    struct perf *prev;
    struct perf *cur;

    ASSERT(SIZE(metric_names) == PERF_N);
    push_perf_index(type);

    prev = get_perf(-2);
    cur = get_perf(-1);

    ASSERT(cur);

    if (prev)
    {
        perf_interrupt(prev);
    }
    perf_start(cur);
}

void
perf_pop(void)
{
    struct perf *prev;
    struct perf *cur;

    prev = get_perf(-2);
    cur = get_perf(-1);

    ASSERT(cur);
    perf_stop(cur);

    if (prev)
    {
        perf_resume(prev);
    }

    pop_perf_index();
}

void
perf_output_results(void)
{
    int i;
    msg(M_INFO, "LATENCY PROFILE (mean and max are in milliseconds)");
    for (i = 0; i < PERF_N; ++i)
    {
        struct perf *p = &perf_set.perf[i];
        if (p->count > 0.0)
        {
            const double mean = p->sum / p->count;
            msg(M_INFO, "%s n=%.0f mean=%.3f max=%.3f", metric_names[i], p->count, mean*1000.0, p->max*1000.0);
        }
    }
}

static void
perf_print_state(int lev)
{
    struct gc_arena gc = gc_new();
    int i;
    msg(lev, "PERF STATE");
    msg(lev, "Stack:");
    for (i = 0; i < perf_set.stack_len; ++i)
    {
        const int j = perf_set.stack[i];
        const struct perf *p = &perf_set.perf[j];
        msg(lev, "[%d] %s state=%d start=%s sofar=%f sum=%f max=%f count=%f",
            i,
            metric_names[j],
            p->state,
            tv_string(&p->start, &gc),
            p->sofar,
            p->sum,
            p->max,
            p->count);
    }
    gc_free(&gc);
}

#else  /* ifdef ENABLE_PERFORMANCE_METRICS */
#ifdef _MSC_VER  /* Dummy function needed to avoid empty file compiler warning in Microsoft VC */
static void
dummy(void)
{
}
#endif
#endif /* ifdef ENABLE_PERFORMANCE_METRICS */
