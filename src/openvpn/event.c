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

#include "buffer.h"
#include "error.h"
#include "integer.h"
#include "event.h"
#include "fdmisc.h"

#if EPOLL
#include <sys/epoll.h>
#endif

#include "memdbg.h"

/*
 * Some OSes will prefer select() over poll()
 * when both are available.
 */
#if defined(TARGET_DARWIN)
#define SELECT_PREFERRED_OVER_POLL
#endif

/*
 * All non-windows OSes are assumed to have select()
 */
#define SELECT 1

/*
 * This should be set to the highest file descriptor
 * which can be used in one of the FD_ macros.
 */
#ifdef FD_SETSIZE
#define SELECT_MAX_FDS FD_SETSIZE
#else
#define SELECT_MAX_FDS 256
#endif

/** Convert \c timeval value (which is in seconds and microseconds)
    to a value of milliseconds which is required by multiple polling
    APIs.

    @param tv \c timeval to convert

    @return Milliseconds to wait. Zero if \p tv is zero.
     Otherwise the return value is always greater than zero.
*/
static inline int
tv_to_ms_timeout(const struct timeval *tv)
{
    if (tv->tv_sec == 0 && tv->tv_usec == 0)
    {
        return 0;
    }
    else
    {
        /* might overflow but not for practically useful numbers */
        return max_int((int)(tv->tv_sec * 1000 + (tv->tv_usec + 500) / 1000), 1);
    }
}

#if EPOLL

struct ep_set
{
    struct event_set_functions func;
    bool fast;
    int epfd;
    int maxevents;
    struct epoll_event *events;
};

static void
ep_free(struct event_set *es)
{
    struct ep_set *eps = (struct ep_set *)es;
    close(eps->epfd);
    free(eps->events);
    free(eps);
}

static void
ep_reset(struct event_set *es)
{
    const struct ep_set *eps = (struct ep_set *)es;
    ASSERT(eps->fast);
}

static void
ep_del(struct event_set *es, event_t event)
{
    struct epoll_event ev;
    struct ep_set *eps = (struct ep_set *)es;

    dmsg(D_EVENT_WAIT, "EP_DEL ev=%d", (int)event);

    ASSERT(!eps->fast);
    CLEAR(ev);
    if (epoll_ctl(eps->epfd, EPOLL_CTL_DEL, event, &ev) < 0)
    {
        msg(M_WARN | M_ERRNO, "EVENT: epoll_ctl EPOLL_CTL_DEL failed, sd=%d", (int)event);
    }
}

static void
ep_ctl(struct event_set *es, event_t event, unsigned int rwflags, void *arg)
{
    struct ep_set *eps = (struct ep_set *)es;
    struct epoll_event ev;

    CLEAR(ev);

    ev.data.ptr = arg;
    if (rwflags & EVENT_READ)
    {
        ev.events |= EPOLLIN;
    }
    if (rwflags & EVENT_WRITE)
    {
        ev.events |= EPOLLOUT;
    }

    dmsg(D_EVENT_WAIT, "EP_CTL fd=%d rwflags=0x%04x ev=0x%08x arg=" ptr_format, (int)event, rwflags,
         (unsigned int)ev.events, (ptr_type)ev.data.ptr);

    if (epoll_ctl(eps->epfd, EPOLL_CTL_MOD, event, &ev) < 0)
    {
        if (errno == ENOENT)
        {
            if (epoll_ctl(eps->epfd, EPOLL_CTL_ADD, event, &ev) < 0)
            {
                msg(M_ERR, "EVENT: epoll_ctl EPOLL_CTL_ADD failed, sd=%d", (int)event);
            }
        }
        else
        {
            msg(M_ERR, "EVENT: epoll_ctl EPOLL_CTL_MOD failed, sd=%d", (int)event);
        }
    }
}

static int
ep_wait(struct event_set *es, const struct timeval *tv, struct event_set_return *out, int outlen)
{
    struct ep_set *eps = (struct ep_set *)es;
    int stat;

    if (outlen > eps->maxevents)
    {
        outlen = eps->maxevents;
    }

    stat = epoll_wait(eps->epfd, eps->events, outlen, tv_to_ms_timeout(tv));
    ASSERT(stat <= outlen);

    if (stat > 0)
    {
        int i;
        const struct epoll_event *ev = eps->events;
        struct event_set_return *esr = out;
        for (i = 0; i < stat; ++i)
        {
            esr->rwflags = 0;
            if (ev->events & (EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP))
            {
                esr->rwflags |= EVENT_READ;
            }
            if (ev->events & EPOLLOUT)
            {
                esr->rwflags |= EVENT_WRITE;
            }
            esr->arg = ev->data.ptr;
            dmsg(D_EVENT_WAIT, "EP_WAIT[%d] rwflags=0x%04x ev=0x%08x arg=" ptr_format, i,
                 esr->rwflags, ev->events, (ptr_type)ev->data.ptr);
            ++ev;
            ++esr;
        }
    }
    return stat;
}

static struct event_set *
ep_init(int *maxevents, unsigned int flags)
{
    struct ep_set *eps;
    int fd;

    dmsg(D_EVENT_WAIT, "EP_INIT maxevents=%d flags=0x%08x", *maxevents, flags);

    /* open epoll file descriptor */
    fd = epoll_create(*maxevents);
    if (fd < 0)
    {
        return NULL;
    }

    set_cloexec(fd);

    ALLOC_OBJ_CLEAR(eps, struct ep_set);

    /* set dispatch functions */
    eps->func.free = ep_free;
    eps->func.reset = ep_reset;
    eps->func.del = ep_del;
    eps->func.ctl = ep_ctl;
    eps->func.wait = ep_wait;

    /* fast method ("sort of") corresponds to epoll one-shot */
    if (flags & EVENT_METHOD_FAST)
    {
        eps->fast = true;
    }

    /* allocate space for epoll_wait return */
    ASSERT(*maxevents > 0);
    eps->maxevents = *maxevents;
    ALLOC_ARRAY_CLEAR(eps->events, struct epoll_event, eps->maxevents);

    /* set epoll control fd */
    eps->epfd = fd;

    return (struct event_set *)eps;
}
#endif /* EPOLL */

#if POLL

struct po_set
{
    struct event_set_functions func;
    bool fast;
    struct pollfd *events;
    void **args;
    int n_events;
    int capacity;
};

static void
po_free(struct event_set *es)
{
    struct po_set *pos = (struct po_set *)es;
    free(pos->events);
    free(pos->args);
    free(pos);
}

static void
po_reset(struct event_set *es)
{
    struct po_set *pos = (struct po_set *)es;
    ASSERT(pos->fast);
    pos->n_events = 0;
}

static void
po_del(struct event_set *es, event_t event)
{
    struct po_set *pos = (struct po_set *)es;
    int i;

    dmsg(D_EVENT_WAIT, "PO_DEL ev=%d", (int)event);

    ASSERT(!pos->fast);
    for (i = 0; i < pos->n_events; ++i)
    {
        if (pos->events[i].fd == event)
        {
            int j;
            for (j = i; j < pos->n_events - 1; ++j)
            {
                pos->events[j] = pos->events[j + 1];
                pos->args[j] = pos->args[j + 1];
            }
            --pos->n_events;
            break;
        }
    }
}

static inline void
po_set_pollfd_events(struct pollfd *pfdp, unsigned int rwflags)
{
    pfdp->events = 0;
    if (rwflags & EVENT_WRITE)
    {
        pfdp->events |= POLLOUT;
    }
    if (rwflags & EVENT_READ)
    {
        pfdp->events |= (POLLIN | POLLPRI);
    }
}

static inline bool
po_append_event(struct po_set *pos, event_t event, unsigned int rwflags, void *arg)
{
    if (pos->n_events < pos->capacity)
    {
        struct pollfd *pfdp = &pos->events[pos->n_events];
        pfdp->fd = event;
        pos->args[pos->n_events] = arg;
        po_set_pollfd_events(pfdp, rwflags);
        ++pos->n_events;
        return true;
    }
    else
    {
        return false;
    }
}

static void
po_ctl(struct event_set *es, event_t event, unsigned int rwflags, void *arg)
{
    struct po_set *pos = (struct po_set *)es;

    dmsg(D_EVENT_WAIT, "PO_CTL rwflags=0x%04x ev=%d arg=" ptr_format, rwflags, (int)event,
         (ptr_type)arg);

    if (pos->fast)
    {
        if (!po_append_event(pos, event, rwflags, arg))
        {
            goto err;
        }
    }
    else
    {
        int i;
        for (i = 0; i < pos->n_events; ++i)
        {
            struct pollfd *pfdp = &pos->events[i];
            if (pfdp->fd == event)
            {
                pos->args[i] = arg;
                po_set_pollfd_events(pfdp, rwflags);
                goto done;
            }
        }
        if (!po_append_event(pos, event, rwflags, arg))
        {
            goto err;
        }
    }

done:
    return;

err:
    msg(D_EVENT_ERRORS, "Error: poll: too many I/O wait events");
}

static int
po_wait(struct event_set *es, const struct timeval *tv, struct event_set_return *out, int outlen)
{
    struct po_set *pos = (struct po_set *)es;
    int stat;

    stat = poll(pos->events, pos->n_events, tv_to_ms_timeout(tv));

    ASSERT(stat <= pos->n_events);

    if (stat > 0)
    {
        int i, j = 0;
        const struct pollfd *pfdp = pos->events;
        for (i = 0; i < pos->n_events && j < outlen; ++i)
        {
            if (pfdp->revents & (POLLIN | POLLPRI | POLLERR | POLLHUP | POLLOUT))
            {
                out->rwflags = 0;
                if (pfdp->revents & (POLLIN | POLLPRI | POLLERR | POLLHUP))
                {
                    out->rwflags |= EVENT_READ;
                }
                if (pfdp->revents & POLLOUT)
                {
                    out->rwflags |= EVENT_WRITE;
                }
                out->arg = pos->args[i];
                dmsg(D_EVENT_WAIT,
                     "PO_WAIT[%d,%d] fd=%d rev=0x%08x rwflags=0x%04x arg=" ptr_format " %s", i, j,
                     pfdp->fd, pfdp->revents, out->rwflags, (ptr_type)out->arg,
                     pos->fast ? "" : "[scalable]");
                ++out;
                ++j;
            }
            else if (pfdp->revents)
            {
                msg(D_EVENT_ERRORS, "Error: poll: unknown revents=0x%04x for fd=%d",
                    (unsigned int)pfdp->revents, pfdp->fd);
            }
            ++pfdp;
        }
        return j;
    }
    return stat;
}

static struct event_set *
po_init(int *maxevents, unsigned int flags)
{
    struct po_set *pos;

    dmsg(D_EVENT_WAIT, "PO_INIT maxevents=%d flags=0x%08x", *maxevents, flags);

    ALLOC_OBJ_CLEAR(pos, struct po_set);

    /* set dispatch functions */
    pos->func.free = po_free;
    pos->func.reset = po_reset;
    pos->func.del = po_del;
    pos->func.ctl = po_ctl;
    pos->func.wait = po_wait;

    if (flags & EVENT_METHOD_FAST)
    {
        pos->fast = true;
    }

    pos->n_events = 0;

    /* Figure our event capacity */
    ASSERT(*maxevents > 0);
    pos->capacity = *maxevents;

    /* Allocate space for pollfd structures to be passed to poll() */
    ALLOC_ARRAY_CLEAR(pos->events, struct pollfd, pos->capacity);

    /* Allocate space for event_set_return objects */
    ALLOC_ARRAY_CLEAR(pos->args, void *, pos->capacity);

    return (struct event_set *)pos;
}
#endif /* POLL */

#if SELECT

struct se_set
{
    struct event_set_functions func;
    bool fast;
    fd_set readfds;
    fd_set writefds;
    void **args;  /* allocated to capacity size */
    int maxfd;    /* largest fd seen so far, always < capacity */
    int capacity; /* fixed largest fd + 1 */
};

static void
se_free(struct event_set *es)
{
    struct se_set *ses = (struct se_set *)es;
    free(ses->args);
    free(ses);
}

static void
se_reset(struct event_set *es)
{
    struct se_set *ses = (struct se_set *)es;
    int i;
    ASSERT(ses->fast);

    dmsg(D_EVENT_WAIT, "SE_RESET");

    FD_ZERO(&ses->readfds);
    FD_ZERO(&ses->writefds);
    for (i = 0; i <= ses->maxfd; ++i)
    {
        ses->args[i] = NULL;
    }
    ses->maxfd = -1;
}

static void
se_del(struct event_set *es, event_t event)
{
    struct se_set *ses = (struct se_set *)es;
    ASSERT(!ses->fast);

    dmsg(D_EVENT_WAIT, "SE_DEL ev=%d", (int)event);

    if (event >= 0 && event < ses->capacity)
    {
        FD_CLR(event, &ses->readfds);
        FD_CLR(event, &ses->writefds);
        ses->args[event] = NULL;
    }
    else
    {
        msg(D_EVENT_ERRORS, "Error: select/se_del: too many I/O wait events");
    }
    return;
}

static void
se_ctl(struct event_set *es, event_t event, unsigned int rwflags, void *arg)
{
    struct se_set *ses = (struct se_set *)es;

    dmsg(D_EVENT_WAIT, "SE_CTL rwflags=0x%04x ev=%d fast=%d cap=%d maxfd=%d arg=" ptr_format,
         rwflags, (int)event, (int)ses->fast, ses->capacity, ses->maxfd, (ptr_type)arg);

    if (event >= 0 && event < ses->capacity)
    {
        ses->maxfd = max_int(event, ses->maxfd);
        ses->args[event] = arg;
        if (ses->fast)
        {
            if (rwflags & EVENT_READ)
            {
                openvpn_fd_set(event, &ses->readfds);
            }
            if (rwflags & EVENT_WRITE)
            {
                openvpn_fd_set(event, &ses->writefds);
            }
        }
        else
        {
            if (rwflags & EVENT_READ)
            {
                openvpn_fd_set(event, &ses->readfds);
            }
            else
            {
                FD_CLR(event, &ses->readfds);
            }
            if (rwflags & EVENT_WRITE)
            {
                openvpn_fd_set(event, &ses->writefds);
            }
            else
            {
                FD_CLR(event, &ses->writefds);
            }
        }
    }
    else
    {
        msg(D_EVENT_ERRORS, "Error: select: too many I/O wait events, fd=%d cap=%d", (int)event,
            ses->capacity);
    }
}

static int
se_wait_return(struct se_set *ses, fd_set *read, fd_set *write, struct event_set_return *out,
               int outlen)
{
    int i, j = 0;
    for (i = 0; i <= ses->maxfd && j < outlen; ++i)
    {
        const bool r = FD_ISSET(i, read);
        const bool w = FD_ISSET(i, write);
        if (r || w)
        {
            out->rwflags = 0;
            if (r)
            {
                out->rwflags |= EVENT_READ;
            }
            if (w)
            {
                out->rwflags |= EVENT_WRITE;
            }
            out->arg = ses->args[i];
            dmsg(D_EVENT_WAIT, "SE_WAIT[%d,%d] rwflags=0x%04x arg=" ptr_format, i, j, out->rwflags,
                 (ptr_type)out->arg);
            ++out;
            ++j;
        }
    }
    return j;
}

static int
se_wait_fast(struct event_set *es, const struct timeval *tv, struct event_set_return *out,
             int outlen)
{
    struct se_set *ses = (struct se_set *)es;
    struct timeval tv_tmp = *tv;
    int stat;

    dmsg(D_EVENT_WAIT, "SE_WAIT_FAST maxfd=%d tv=%" PRIi64 "/%ld", ses->maxfd,
         (int64_t)tv_tmp.tv_sec, (long)tv_tmp.tv_usec);

    stat = select(ses->maxfd + 1, &ses->readfds, &ses->writefds, NULL, &tv_tmp);

    if (stat > 0)
    {
        stat = se_wait_return(ses, &ses->readfds, &ses->writefds, out, outlen);
    }

    return stat;
}

static int
se_wait_scalable(struct event_set *es, const struct timeval *tv, struct event_set_return *out,
                 int outlen)
{
    struct se_set *ses = (struct se_set *)es;
    struct timeval tv_tmp = *tv;
    fd_set read = ses->readfds;
    fd_set write = ses->writefds;
    int stat;

    dmsg(D_EVENT_WAIT, "SE_WAIT_SCALEABLE maxfd=%d tv=%" PRIi64 "/%ld", ses->maxfd,
         (int64_t)tv_tmp.tv_sec, (long)tv_tmp.tv_usec);

    stat = select(ses->maxfd + 1, &read, &write, NULL, &tv_tmp);

    if (stat > 0)
    {
        stat = se_wait_return(ses, &read, &write, out, outlen);
    }

    return stat;
}

static struct event_set *
se_init(int *maxevents, unsigned int flags)
{
    struct se_set *ses;

    dmsg(D_EVENT_WAIT, "SE_INIT maxevents=%d flags=0x%08x", *maxevents, flags);

    ALLOC_OBJ_CLEAR(ses, struct se_set);

    /* set dispatch functions */
    ses->func.free = se_free;
    ses->func.reset = se_reset;
    ses->func.del = se_del;
    ses->func.ctl = se_ctl;
    ses->func.wait = se_wait_scalable;

    if (flags & EVENT_METHOD_FAST)
    {
        ses->fast = true;
        ses->func.wait = se_wait_fast;
    }

    /* Select needs to be passed this value + 1 */
    ses->maxfd = -1;

    /* Set our event capacity */
    ASSERT(*maxevents > 0);
    *maxevents = min_int(*maxevents, SELECT_MAX_FDS);
    ses->capacity = SELECT_MAX_FDS;

    /* Allocate space for event_set_return void * args */
    ALLOC_ARRAY_CLEAR(ses->args, void *, ses->capacity);

    return (struct event_set *)ses;
}
#endif /* SELECT */

static struct event_set *
event_set_init_simple(int *maxevents, unsigned int flags)
{
    struct event_set *ret = NULL;
#if POLL && SELECT
#ifdef SELECT_PREFERRED_OVER_POLL
    if (!ret)
    {
        ret = se_init(maxevents, flags);
    }
    if (!ret)
    {
        ret = po_init(maxevents, flags);
    }
#else /* ifdef SELECT_PREFERRED_OVER_POLL */
    if (!ret)
    {
        ret = po_init(maxevents, flags);
    }
    if (!ret)
    {
        ret = se_init(maxevents, flags);
    }
#endif
#elif POLL
    ret = po_init(maxevents, flags);
#elif SELECT
    ret = se_init(maxevents, flags);
#else
#error At least one of poll, select, or WSAWaitForMultipleEvents must be supported by the kernel
#endif
    ASSERT(ret);
    return ret;
}

static struct event_set *
event_set_init_scalable(int *maxevents, unsigned int flags)
{
    struct event_set *ret = NULL;
#if EPOLL
    ret = ep_init(maxevents, flags);
    if (!ret)
    {
        msg(M_WARN, "Note: sys_epoll API is unavailable, falling back to poll/select API");
        ret = event_set_init_simple(maxevents, flags);
    }
#else /* if EPOLL */
    ret = event_set_init_simple(maxevents, flags);
#endif
    ASSERT(ret);
    return ret;
}

struct event_set *
event_set_init(int *maxevents, unsigned int flags)
{
    if (flags & EVENT_METHOD_FAST)
    {
        return event_set_init_simple(maxevents, flags);
    }
    else
    {
        return event_set_init_scalable(maxevents, flags);
    }
}
