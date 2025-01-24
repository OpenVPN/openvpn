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

#include "memdbg.h"

#include "multi.h"
#include "forward.h"
#include "multi_io.h"

#ifdef HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#endif

/*
 * Special tags passed to event.[ch] functions
 */
#define MULTI_IO_SOCKET      ((void *)1)
#define MULTI_IO_TUN         ((void *)2)
#define MULTI_IO_SIG         ((void *)3) /* Only on Windows */
#define MULTI_IO_MANAGEMENT ((void *)4)
#define MULTI_IO_FILE_CLOSE_WRITE ((void *)5)
#define MULTI_IO_DCO        ((void *)6)

struct ta_iow_flags
{
    unsigned int flags;
    unsigned int ret;
    unsigned int tun;
    unsigned int sock;
};

#ifdef ENABLE_DEBUG
static const char *
pract(int action)
{
    switch (action)
    {
        case TA_UNDEF:
            return "TA_UNDEF";

        case TA_SOCKET_READ:
            return "TA_SOCKET_READ";

        case TA_SOCKET_READ_RESIDUAL:
            return "TA_SOCKET_READ_RESIDUAL";

        case TA_SOCKET_WRITE:
            return "TA_SOCKET_WRITE";

        case TA_SOCKET_WRITE_READY:
            return "TA_SOCKET_WRITE_READY";

        case TA_SOCKET_WRITE_DEFERRED:
            return "TA_SOCKET_WRITE_DEFERRED";

        case TA_TUN_READ:
            return "TA_TUN_READ";

        case TA_TUN_WRITE:
            return "TA_TUN_WRITE";

        case TA_INITIAL:
            return "TA_INITIAL";

        case TA_TIMEOUT:
            return "TA_TIMEOUT";

        case TA_TUN_WRITE_TIMEOUT:
            return "TA_TUN_WRITE_TIMEOUT";

        default:
            return "?";
    }
}
#endif /* ENABLE_DEBUG */

static inline struct context *
multi_get_context(struct multi_context *m, struct multi_instance *mi)
{
    if (mi)
    {
        return &mi->context;
    }
    else
    {
        return &m->top;
    }
}

struct multi_io *
multi_io_init(int maxevents, int *maxclients)
{
    struct multi_io *multi_io;
    const int extra_events = BASE_N_EVENTS;

    ASSERT(maxevents >= 1);
    ASSERT(maxclients);

    ALLOC_OBJ_CLEAR(multi_io, struct multi_io);
    multi_io->maxevents = maxevents + extra_events;
    multi_io->es = event_set_init(&multi_io->maxevents, 0);
    wait_signal(multi_io->es, MULTI_IO_SIG);
    ALLOC_ARRAY(multi_io->esr, struct event_set_return, multi_io->maxevents);
    *maxclients = max_int(min_int(multi_io->maxevents - extra_events, *maxclients), 1);
    msg(D_MULTI_LOW, "MULTI IO: MULTI_IO INIT maxclients=%d maxevents=%d", *maxclients, multi_io->maxevents);
    return multi_io;
}

void
multi_io_free(struct multi_io *multi_io)
{
    if (multi_io)
    {
        event_free(multi_io->es);
        free(multi_io->esr);
        free(multi_io);
    }
}

int
multi_io_wait(struct multi_context *m)
{
    int status, i;
    unsigned int *persistent = &m->multi_io->tun_rwflags;

    for (i = 0; i < m->top.c1.link_sockets_num; i++)
    {
        socket_set_listen_persistent(m->top.c2.link_sockets[i], m->multi_io->es,
                                     &m->top.c2.link_sockets[i]->ev_arg);
    }

#ifdef _WIN32
    if (tuntap_is_wintun(m->top.c1.tuntap))
    {
        if (!tuntap_ring_empty(m->top.c1.tuntap))
        {
            /* there is data in wintun ring buffer, read it immediately */
            m->multi_io->esr[0].arg = MULTI_IO_TUN;
            m->multi_io->esr[0].rwflags = EVENT_READ;
            m->multi_io->n_esr = 1;
            return 1;
        }
        persistent = NULL;
    }
#endif
    tun_set(m->top.c1.tuntap, m->multi_io->es, EVENT_READ, MULTI_IO_TUN, persistent);
#if defined(TARGET_LINUX) || defined(TARGET_FREEBSD)
    dco_event_set(&m->top.c1.tuntap->dco, m->multi_io->es, MULTI_IO_DCO);
#endif

#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_socket_set(management, m->multi_io->es, MULTI_IO_MANAGEMENT, &m->multi_io->management_persist_flags);
    }
#endif

#ifdef ENABLE_ASYNC_PUSH
    /* arm inotify watcher */
    event_ctl(m->multi_io->es, m->top.c2.inotify_fd, EVENT_READ, MULTI_IO_FILE_CLOSE_WRITE);
#endif

    status = event_wait(m->multi_io->es, &m->top.c2.timeval, m->multi_io->esr, m->multi_io->maxevents);
    update_time();
    m->multi_io->n_esr = 0;
    if (status > 0)
    {
        m->multi_io->n_esr = status;
    }
    return status;
}

static int
multi_io_wait_lite(struct multi_context *m, struct multi_instance *mi, const int action, bool *tun_input_pending)
{
    struct context *c = multi_get_context(m, mi);
    unsigned int looking_for = 0;

    dmsg(D_MULTI_DEBUG, "MULTI IO: multi_io_wait_lite a=%s mi=" ptr_format,
         pract(action),
         (ptr_type)mi);

    tv_clear(&c->c2.timeval); /* ZERO-TIMEOUT */

    switch (action)
    {
        case TA_TUN_READ:
            looking_for = TUN_READ;
            tun_input_pending = NULL;
            io_wait(c, IOW_READ_TUN);
            break;

        case TA_SOCKET_READ:
            looking_for = SOCKET_READ;
            tun_input_pending = NULL;
            io_wait(c, IOW_READ_LINK);
            break;

        case TA_TUN_WRITE:
            looking_for = TUN_WRITE;
            tun_input_pending = NULL;
            c->c2.timeval.tv_sec = 1; /* For some reason, the Linux 2.2 TUN/TAP driver hits this timeout */
            perf_push(PERF_PROC_OUT_TUN_MTCP);
            io_wait(c, IOW_TO_TUN);
            perf_pop();
            break;

        case TA_SOCKET_WRITE:
            looking_for = SOCKET_WRITE;
            io_wait(c, IOW_TO_LINK|IOW_READ_TUN_FORCE);
            break;

        default:
            msg(M_FATAL, "MULTI IO: multi_io_wait_lite, unhandled action=%d", action);
    }

    if (tun_input_pending && (c->c2.event_set_status & TUN_READ))
    {
        *tun_input_pending = true;
    }

    if (c->c2.event_set_status & looking_for)
    {
        return action;
    }
    else
    {
        switch (action)
        {
            /* MULTI PROTOCOL socket output buffer is full */
            case TA_SOCKET_WRITE:
                return TA_SOCKET_WRITE_DEFERRED;

            /* TUN device timed out on accepting write */
            case TA_TUN_WRITE:
                return TA_TUN_WRITE_TIMEOUT;
        }

        return TA_UNDEF;
    }
}

static struct multi_instance *
multi_io_dispatch(struct multi_context *m, struct multi_instance *mi, const int action)
{
    const unsigned int mpp_flags = MPP_PRE_SELECT|MPP_RECORD_TOUCH;
    struct multi_instance *touched = mi;
    m->mpp_touched = &touched;

    dmsg(D_MULTI_DEBUG, "MULTI IO: multi_io_dispatch a=%s mi=" ptr_format,
         pract(action),
         (ptr_type)mi);

    switch (action)
    {
        case TA_TUN_READ:
            read_incoming_tun(&m->top);
            if (!IS_SIG(&m->top))
            {
                multi_process_incoming_tun(m, mpp_flags);
            }
            break;

        case TA_SOCKET_READ:
        case TA_SOCKET_READ_RESIDUAL:
            ASSERT(mi);
            ASSERT(mi->context.c2.link_sockets);
            ASSERT(mi->context.c2.link_sockets[0]);
            set_prefix(mi);
            read_incoming_link(&mi->context, mi->context.c2.link_sockets[0]);
            clear_prefix();
            if (!IS_SIG(&mi->context))
            {
                multi_process_incoming_link(m, mi, mpp_flags,
                                            mi->context.c2.link_sockets[0]);
                if (!IS_SIG(&mi->context))
                {
                    stream_buf_read_setup(mi->context.c2.link_sockets[0]);
                }
            }
            break;

        case TA_TIMEOUT:
            multi_process_timeout(m, mpp_flags);
            break;

        case TA_TUN_WRITE:
            multi_process_outgoing_tun(m, mpp_flags);
            break;

        case TA_TUN_WRITE_TIMEOUT:
            multi_process_drop_outgoing_tun(m, mpp_flags);
            break;

        case TA_SOCKET_WRITE_READY:
            ASSERT(mi);
            multi_tcp_process_outgoing_link_ready(m, mi, mpp_flags);
            break;

        case TA_SOCKET_WRITE:
            multi_tcp_process_outgoing_link(m, false, mpp_flags);
            break;

        case TA_SOCKET_WRITE_DEFERRED:
            multi_tcp_process_outgoing_link(m, true, mpp_flags);
            break;

        case TA_INITIAL:
            ASSERT(mi);
            multi_tcp_set_global_rw_flags(m, mi);
            multi_process_post(m, mi, mpp_flags);
            break;

        default:
            msg(M_FATAL, "MULTI IO: multi_io_dispatch, unhandled action=%d", action);
    }

    m->mpp_touched = NULL;
    return touched;
}

static int
multi_io_post(struct multi_context *m, struct multi_instance *mi, const int action)
{
    struct context *c = multi_get_context(m, mi);
    int newaction = TA_UNDEF;

#define MTP_NONE         0
#define MTP_TUN_OUT      (1<<0)
#define MTP_LINK_OUT     (1<<1)
    unsigned int flags = MTP_NONE;

    if (TUN_OUT(c))
    {
        flags |= MTP_TUN_OUT;
    }
    if (LINK_OUT(c))
    {
        flags |= MTP_LINK_OUT;
    }

    switch (flags)
    {
        case MTP_TUN_OUT|MTP_LINK_OUT:
        case MTP_TUN_OUT:
            newaction = TA_TUN_WRITE;
            break;

        case MTP_LINK_OUT:
            newaction = TA_SOCKET_WRITE;
            break;

        case MTP_NONE:
            if (mi && sockets_read_residual(c))
            {
                newaction = TA_SOCKET_READ_RESIDUAL;
            }
            else
            {
                multi_tcp_set_global_rw_flags(m, mi);
            }
            break;

        default:
        {
            struct gc_arena gc = gc_new();
            msg(M_FATAL, "MULTI IO: multi_io_post bad state, mi=%s flags=%d",
                multi_instance_string(mi, false, &gc),
                flags);
            gc_free(&gc);
            break;
        }
    }

    dmsg(D_MULTI_DEBUG, "MULTI IO: multi_io_post %s -> %s",
         pract(action),
         pract(newaction));

    return newaction;
}

void
multi_io_process_io(struct multi_context *m)
{
    struct multi_io *multi_io = m->multi_io;
    int i;

    for (i = 0; i < multi_io->n_esr; ++i)
    {
        struct event_set_return *e = &multi_io->esr[i];
        struct event_arg *ev_arg = (struct event_arg *)e->arg;

        /* incoming data for instance or listening socket? */
        if (e->arg >= MULTI_N)
        {
            switch (ev_arg->type)
            {
                struct multi_instance *mi;

                /* react to event on child instance */
                case EVENT_ARG_MULTI_INSTANCE:
                    if (!ev_arg->u.mi)
                    {
                        msg(D_MULTI_ERRORS, "MULTI IO: multi_io_proc_io: null minstance");
                        break;
                    }

                    mi = ev_arg->u.mi;
                    if (e->rwflags & EVENT_WRITE)
                    {
                        multi_io_action(m, mi, TA_SOCKET_WRITE_READY, false);
                    }
                    else if (e->rwflags & EVENT_READ)
                    {
                        multi_io_action(m, mi, TA_SOCKET_READ, false);
                    }
                    break;

                /* new incoming TCP client attempting to connect? */
                case EVENT_ARG_LINK_SOCKET:
                    if (!ev_arg->u.sock)
                    {
                        msg(D_MULTI_ERRORS, "MULTI IO: multi_io_proc_io: null socket");
                        break;
                    }

                    if (!proto_is_dgram(ev_arg->u.sock->info.proto))
                    {
                        socket_reset_listen_persistent(ev_arg->u.sock);
                        mi = multi_create_instance_tcp(m, ev_arg->u.sock);
                        if (mi)
                        {
                            multi_io_action(m, mi, TA_INITIAL, false);
                        }
                        break;
                    }
            }
        }
        else
        {
#ifdef ENABLE_MANAGEMENT
            if (e->arg == MULTI_IO_MANAGEMENT)
            {
                ASSERT(management);
                management_io(management);
            }
            else
#endif
            /* incoming data on TUN? */
            if (e->arg == MULTI_IO_TUN)
            {
                if (e->rwflags & EVENT_WRITE)
                {
                    multi_io_action(m, NULL, TA_TUN_WRITE, false);
                }
                else if (e->rwflags & EVENT_READ)
                {
                    multi_io_action(m, NULL, TA_TUN_READ, false);
                }
            }
            /* new incoming TCP client attempting to connect? */
            else if (e->arg == MULTI_IO_SOCKET)
            {
                struct multi_instance *mi;
                ASSERT(m->top.c2.link_sockets[0]);
                socket_reset_listen_persistent(m->top.c2.link_sockets[0]);
                mi = multi_create_instance_tcp(m, m->top.c2.link_sockets[0]);
                if (mi)
                {
                    multi_io_action(m, mi, TA_INITIAL, false);
                }
            }
#if defined(ENABLE_DCO) && (defined(TARGET_LINUX) || defined(TARGET_FREEBSD))
            /* incoming data on DCO? */
            else if (e->arg == MULTI_IO_DCO)
            {
                multi_process_incoming_dco(m);
            }
#endif
            /* signal received? */
            else if (e->arg == MULTI_IO_SIG)
            {
                get_signal(&m->top.sig->signal_received);
            }
#ifdef ENABLE_ASYNC_PUSH
            else if (e->arg == MULTI_IO_FILE_CLOSE_WRITE)
            {
                multi_process_file_closed(m, MPP_PRE_SELECT | MPP_RECORD_TOUCH);
            }
#endif
        }
        if (IS_SIG(&m->top))
        {
            break;
        }
    }
    multi_io->n_esr = 0;

    /*
     * Process queued mbuf packets destined for TCP socket
     */
    {
        struct multi_instance *mi;
        while (!IS_SIG(&m->top) && (mi = mbuf_peek(m->mbuf)) != NULL)
        {
            multi_io_action(m, mi, TA_SOCKET_WRITE, true);
        }
    }
}

void
multi_io_action(struct multi_context *m, struct multi_instance *mi, int action, bool poll)
{
    bool tun_input_pending = false;

    do
    {
        dmsg(D_MULTI_DEBUG, "MULTI IO: multi_io_action a=%s p=%d",
             pract(action),
             poll);

        /*
         * If TA_SOCKET_READ_RESIDUAL, it means we still have pending
         * input packets which were read by a prior recv.
         *
         * Otherwise do a "lite" wait, which means we wait with 0 timeout
         * on I/O events only related to the current instance, not
         * the big list of events.
         *
         * On our first pass, poll will be false because we already know
         * that input is available, and to call io_wait would be redundant.
         */
        if (poll && action != TA_SOCKET_READ_RESIDUAL)
        {
            const int orig_action = action;
            action = multi_io_wait_lite(m, mi, action, &tun_input_pending);
            if (action == TA_UNDEF)
            {
                msg(M_FATAL, "MULTI IO: I/O wait required blocking in multi_io_action, action=%d", orig_action);
            }
        }

        /*
         * Dispatch the action
         */
        struct multi_instance *touched = multi_io_dispatch(m, mi, action);

        /*
         * Signal received or connection
         * reset by peer?
         */
        if (touched && IS_SIG(&touched->context))
        {
            if (mi == touched)
            {
                mi = NULL;
            }
            multi_close_instance_on_signal(m, touched);
        }


        /*
         * If dispatch produced any pending output
         * for a particular instance, point to
         * that instance.
         */
        if (m->pending)
        {
            mi = m->pending;
        }

        /*
         * Based on the effects of the action,
         * such as generating pending output,
         * possibly transition to a new action state.
         */
        action = multi_io_post(m, mi, action);

        /*
         * If we are finished processing the original action,
         * check if we have any TUN input.  If so, transition
         * our action state to processing this input.
         */
        if (tun_input_pending && action == TA_UNDEF)
        {
            action = TA_TUN_READ;
            mi = NULL;
            tun_input_pending = false;
            poll = false;
        }
        else
        {
            poll = true;
        }

    } while (action != TA_UNDEF);
}

void
multi_io_delete_event(struct multi_io *multi_io, event_t event)
{
    if (multi_io && multi_io->es)
    {
        event_del(multi_io->es, event);
    }
}
