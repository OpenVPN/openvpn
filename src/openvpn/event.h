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

#ifndef EVENT_H
#define EVENT_H

#include "win32.h"
#include "sig.h"
#include "perf.h"

/*
 * rwflags passed to event_ctl and returned by
 * struct event_set_return.
 */
#define READ_SHIFT      0
#define WRITE_SHIFT     1

#define EVENT_UNDEF     4
#define EVENT_READ      (1 << READ_SHIFT)
#define EVENT_WRITE     (1 << WRITE_SHIFT)

/* event flags returned by io_wait.
 *
 * All these events are defined as bits in a bitfield.
 * Each event 'type' owns two bits in the bitfield: one for the READ
 * event and one for the WRITE event.
 *
 * For this reason, the specific event bit is calculated by adding
 * the event type identifier (always a multiple of 2, as defined
 * below) to 0 for READ and 1 for WRITE.
 *
 * E.g.
 * MANAGEMENT_SHIFT = 6;  <---- event type identifier
 * MANAGEMENT_READ = (1 << (6 + 0)),  <---- READ event
 * MANAGEMENT_WRITE = (1 << (6 + 1))  <---- WRITE event
 *
 * 'error' and 'file_close' are special and use read/write for different
 * signals.
 */

#define SOCKET_SHIFT        0
#define SOCKET_READ         (1 << (SOCKET_SHIFT + READ_SHIFT))
#define SOCKET_WRITE        (1 << (SOCKET_SHIFT + WRITE_SHIFT))
#define TUN_SHIFT           2
#define TUN_READ            (1 << (TUN_SHIFT + READ_SHIFT))
#define TUN_WRITE           (1 << (TUN_SHIFT + WRITE_SHIFT))
#define ERR_SHIFT           4
#define ES_ERROR            (1 << (ERR_SHIFT + READ_SHIFT))
#define ES_TIMEOUT          (1 << (ERR_SHIFT + WRITE_SHIFT))
#define MANAGEMENT_SHIFT    6
#define MANAGEMENT_READ     (1 << (MANAGEMENT_SHIFT + READ_SHIFT))
#define MANAGEMENT_WRITE    (1 << (MANAGEMENT_SHIFT + WRITE_SHIFT))
#define FILE_SHIFT          8
#define FILE_CLOSED         (1 << (FILE_SHIFT + READ_SHIFT))
#define DCO_SHIFT           10
#define DCO_READ            (1 << (DCO_SHIFT + READ_SHIFT))
#define DCO_WRITE           (1 << (DCO_SHIFT + WRITE_SHIFT))

/*
 * Initialization flags passed to event_set_init
 */
#define EVENT_METHOD_US_TIMEOUT   (1<<0)
#define EVENT_METHOD_FAST         (1<<1)

#ifdef _WIN32

typedef const struct rw_handle *event_t;

#define UNDEFINED_EVENT (NULL)

#else  /* ifdef _WIN32 */

typedef int event_t;

#define UNDEFINED_EVENT (-1)

#endif

struct event_set;
struct event_set_return;

struct event_set_functions
{
    void (*free)(struct event_set *es);
    void (*reset)(struct event_set *es);
    void (*del)(struct event_set *es, event_t event);
    void (*ctl)(struct event_set *es, event_t event, unsigned int rwflags, void *arg);

    /*
     * Return status for wait:
     * -1 on signal or error
     * 0 on timeout
     * length of event_set_return if at least 1 event is returned
     */
    int (*wait)(struct event_set *es, const struct timeval *tv, struct event_set_return *out, int outlen);
};

struct event_set_return
{
    unsigned int rwflags;
    void *arg;
};

struct event_set
{
    struct event_set_functions func;
};

/*
 * maxevents on input:  desired max number of event_t descriptors
 *                      simultaneously set with event_ctl
 * maxevents on output: may be modified down, depending on limitations
 *                      of underlying API
 * flags:               EVENT_METHOD_x flags
 */
struct event_set *event_set_init(int *maxevents, unsigned int flags);

static inline void
event_free(struct event_set *es)
{
    if (es)
    {
        (*es->func.free)(es);
    }
}

static inline void
event_reset(struct event_set *es)
{
    (*es->func.reset)(es);
}

static inline void
event_del(struct event_set *es, event_t event)
{
    (*es->func.del)(es, event);
}

static inline void
event_ctl(struct event_set *es, event_t event, unsigned int rwflags, void *arg)
{
    (*es->func.ctl)(es, event, rwflags, arg);
}

static inline int
event_wait(struct event_set *es, const struct timeval *tv, struct event_set_return *out, int outlen)
{
    int ret;
    perf_push(PERF_IO_WAIT);
    ret = (*es->func.wait)(es, tv, out, outlen);
    perf_pop();
    return ret;
}

static inline void
event_set_return_init(struct event_set_return *esr)
{
    esr->rwflags = 0;
    esr->arg = NULL;
}

#ifdef _WIN32

static inline void
wait_signal(struct event_set *es, void *arg)
{
    if (HANDLE_DEFINED(win32_signal.in.read))
    {
        event_ctl(es, &win32_signal.in, EVENT_READ, arg);
    }
}

#else  /* ifdef _WIN32 */

static inline void
wait_signal(struct event_set *es, void *arg)
{
}

#endif

#endif /* ifndef EVENT_H */
