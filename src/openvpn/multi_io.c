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
#define MULTI_IO_SOCKET           ((void *)1)
#define MULTI_IO_TUN              ((void *)2)
#define MULTI_IO_SIG              ((void *)3) /* Only on Windows */
#define MULTI_IO_MANAGEMENT       ((void *)4)
#define MULTI_IO_FILE_CLOSE_WRITE ((void *)5)
#define MULTI_IO_DCO              ((void *)6)

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

struct multi_io
multi_io_init(const int maxclients)
{
    struct multi_io multi_io;

    ASSERT(maxclients >= 1);

    //ALLOC_OBJ_CLEAR(multi_io, struct multi_io);
    bzero(&(multi_io), sizeof(struct multi_io));
    multi_io.maxevents = maxclients + BASE_N_EVENTS;
    multi_io.es = event_set_init(&multi_io.maxevents, 0);
    wait_signal(multi_io.es, MULTI_IO_SIG);
    ALLOC_ARRAY(multi_io.esr, struct event_set_return, multi_io.maxevents);
    msg(D_MULTI_LOW, "MULTI IO: MULTI_IO INIT maxclients=%d maxevents=%d", maxclients, multi_io.maxevents);

    return multi_io;
}

void
multi_io_free(struct multi_io *multi_io)
{
    if (multi_io->es)
    {
        for (int x = 0; x < MAX_THREADS; ++x)
        {
            event_free(multi_io[x].es);
            free(multi_io[x].esr);
        }
        //free(multi_io);
    }
}

struct multi_instance *look_left(struct multi_context *m)
{
    for (int i = 0; i < m->max_clients; ++i)
    {
        struct multi_instance *mi = m->instances[i];
        if (!mi) { continue; }
        if (LINK_LEFT(mi))
        {
            return mi;
        }
    }
    return NULL;
}

int
multi_io_wait(struct multi_context *m)
{
    int status;
    struct multi_io *multi_io = &(m->multi_io[THREAD_MAIN]);
    unsigned int *persistent = &multi_io->tun_rwflags;

    for (int i = 0; i < m->top.c1.link_sockets_num; i++)
    {
        socket_set(m->top.c2.link_sockets[i], multi_io->es, EVENT_READ, &m->top.c2.link_sockets[i]->ev_arg, NULL);
    }

    for (int i = 0; i < m->max_clients; ++i)
    {
        struct multi_instance *mi = m->instances[i];
        if (!mi) { continue; }
        if (proto_is_dgram(mi->context.c2.link_sockets[0]->info.proto))
        {
            socket_set(mi->context.c2.link_sockets[0], multi_io->es, EVENT_READ, &mi->context.c2.link_sockets[0]->ev_arg, NULL);
        }
        else
        {
            socket_set(mi->context.c2.link_sockets[0], multi_io->es, EVENT_READ, &mi->ev_arg, NULL);
        }
    }

    if (has_udp_in_local_list(&m->top.options))
    {
        get_io_flags_udp(&m->top, multi_io, p2mp_iow_flags(m));
    }

    tun_set(m->top.c1.tuntap, multi_io->es, EVENT_READ, MULTI_IO_TUN, persistent);
#if defined(ENABLE_DCO)
    dco_event_set(&m->top.c1.tuntap->dco, multi_io->es, MULTI_IO_DCO);
#endif

#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_socket_set(management, multi_io->es, MULTI_IO_MANAGEMENT, &multi_io->management_persist_flags);
    }
#endif

#ifdef ENABLE_ASYNC_PUSH
    /* arm inotify watcher */
    event_ctl(multi_io->es, m->top.c2.inotify_fd, EVENT_READ, MULTI_IO_FILE_CLOSE_WRITE);
#endif

    status = event_wait(multi_io->es, &m->top.c2.timeval, multi_io->esr, multi_io->maxevents);
    update_time();
    multi_io->n_esr = (status > 0) ? status : 0;
    return status;
}

static struct multi_instance *
multi_io_dispatch(struct multi_context *m, struct multi_instance *mi, const int action, const unsigned int add_flags)
{
    const unsigned int mpp_flags = MPP_PRE_SELECT | MPP_RECORD_TOUCH | add_flags;

    dmsg(D_MULTI_DEBUG, "MULTI IO: multi_io_dispatch a=%s mi=" ptr_format, pract(action), (ptr_type)mi);

    if (mi) { mi->post = false; }
    if (m->pending) { m->pending->post = false; }
    if (m->pending2) { m->pending2->post = false; }
    if (m->earliest_wakeup) { m->earliest_wakeup->post = false; }

    switch (action)
    {
        case TA_INST_LENG:
        case TA_TUN_READ:
            threaded_multi_inp_tun(m, mpp_flags);
            break;

        case TA_SOCKET_READ:
        case TA_SOCKET_READ_RESIDUAL:
            ASSERT(mi);
            read_incoming_link(&mi->context, mi->context.c2.link_sockets[0]);
            if (!IS_SIG(&mi->context))
            {
                multi_process_incoming_link(m, mi, mpp_flags, mi->context.c2.link_sockets[0]);
            }
            break;

        case TA_TIMEOUT:
            multi_process_timeout(m, mpp_flags);
            break;

        case TA_TUN_WRITE:
            multi_process_outgoing_tun(m, mpp_flags);
            break;

        case TA_SOCKET_WRITE:
            multi_tcp_process_outgoing_link(m, false, mpp_flags);
            break;

        case TA_INITIAL:
            ASSERT(mi);
            mi->post = true;
            break;

        default:
            msg(M_FATAL, "MULTI IO: multi_io_dispatch, unhandled action=%d", action);
    }

    if (mi)
    {
        set_prefix(mi);
        multi_process_post(m, mi, mpp_flags);
        clear_prefix();
    }
    if (m->pending)
    {
        set_prefix(m->pending);
        multi_process_post(m, m->pending, mpp_flags);
        clear_prefix();
    }
    if (m->pending2)
    {
        set_prefix(m->pending2);
        multi_process_post(m, m->pending2, mpp_flags);
        clear_prefix();
    }
    if (m->earliest_wakeup)
    {
        set_prefix(m->earliest_wakeup);
        multi_process_post(m, m->earliest_wakeup, mpp_flags);
        clear_prefix();
        m->earliest_wakeup = NULL;
    }

    return mi;
}

static int
multi_io_post(struct multi_context *m, struct multi_instance *mi, const int action, int t)
{
    struct context *c = multi_get_context(m, mi);
    int newaction = TA_UNDEF;

    if (LINK_OUT(c))
    {
        if ((t & THREAD_RTWL) != 0)
        {
            newaction = TA_SOCKET_WRITE;
            goto last;
        }
    }
    else if (INST_LENG(m))
    {
        if ((t & THREAD_RTWL) != 0)
        {
            newaction = TA_INST_LENG;
            goto last;
        }
    }

    if (TUN_OUT(c))
    {
        if ((t & THREAD_RLWT) != 0)
        {
            newaction = TA_TUN_WRITE;
            goto last;
        }
    }
    else if (LINK_LEFT(mi))
    {
        if ((t & THREAD_RLWT) != 0)
        {
            newaction = TA_SOCKET_READ_RESIDUAL;
            goto last;
        }
    }

last:
    dmsg(D_MULTI_DEBUG, "MULTI IO: multi_io_post %s -> %s", pract(action), pract(newaction));

    return newaction;
}

void
multi_io_process_io(struct thread_pointer *b, const unsigned int f, int t)
{
    struct multi_context *m = b->p->m[b->i-1];
    struct multi_io *multi_io = &(m->multi_io[t]);
    struct multi_instance *mi;
    int i;

    for (i = 0; i < multi_io->n_esr; ++i)
    {
        struct event_set_return *e = &multi_io->esr[i];
        struct event_arg *ev_arg = (struct event_arg *)e->arg;

        /* incoming data for instance or listening socket? */
        if (e->arg >= MULTI_N)
        {
            /* react to event on child instance */
            if (ev_arg->type == EVENT_ARG_MULTI_INSTANCE)
            {
                ASSERT(ev_arg->u.mi);
                mi = ev_arg->u.mi;
                if (e->rwflags & EVENT_READ)
                {
                    if ((t & THREAD_RLWT) != 0)
                    {
                        multi_io_action(m, mi, TA_SOCKET_READ, false, f, t);
                    }
                }
            }

            /* new incoming TCP client attempting to connect? */
            if (ev_arg->type == EVENT_ARG_LINK_SOCKET)
            {
                /* monitor and/or handle events that are
                 * triggered in succession by the first one
                 * before returning to the main loop. */
                if ((t & THREAD_RTWL) != 0)
                {
                    ASSERT(ev_arg->u.sock);
                    if (!proto_is_dgram(ev_arg->u.sock->info.proto))
                    {
                        socket_reset_listen_persistent(ev_arg->u.sock);
                        mi = multi_create_instance_tcp(b, ev_arg->u.sock);
                        if (mi) { multi_io_action(b->p->p, mi, TA_INITIAL, false, f, t); }
                    }
                    else
                    {
                        multi_process_io_udp(m, ev_arg->u.sock);
                        if (m->pending) { multi_io_action(m, m->pending, TA_INITIAL, false, f, t); }
                        if (m->pending2) { multi_io_action(m, m->pending2, TA_INITIAL, false, f, t); }
                    }
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
#endif
                /* incoming data on TUN? */
                if (e->arg == MULTI_IO_TUN)
                {
                    if (e->rwflags & EVENT_READ)
                    {
                        if ((t & THREAD_RTWL) != 0)
                        {
                            multi_io_action(m, NULL, TA_TUN_READ, false, f, t);
                        }
                    }
                }

                /* new incoming TCP client attempting to connect? */
                if (e->arg == MULTI_IO_SOCKET)
                {
                    if ((t & THREAD_RTWL) != 0)
                    {
                        ASSERT(m->top.c2.link_sockets[0]);
                        socket_reset_listen_persistent(m->top.c2.link_sockets[0]);
                        mi = multi_create_instance_tcp(b, m->top.c2.link_sockets[0]);
                        if (mi) { multi_io_action(b->p->p, mi, TA_INITIAL, false, f, t); }
                    }
                }
#if defined(ENABLE_DCO)
                /* incoming data on DCO? */
                if (e->arg == MULTI_IO_DCO)
                {
                    multi_process_incoming_dco(m);
                }
#endif
                /* signal received? */
                if (e->arg == MULTI_IO_SIG)
                {
                    if ((t & THREAD_RTWL) != 0)
                    {
                        get_signal(&m->top.sig->signal_received);
                    }
                }
#ifdef ENABLE_ASYNC_PUSH
                if (e->arg == MULTI_IO_FILE_CLOSE_WRITE)
                {
                    if ((t & THREAD_RTWL) != 0)
                    {
                        multi_process_file_closed(m, MPP_PRE_SELECT | MPP_RECORD_TOUCH | f);
                    }
                }
#endif
        }
        if (IS_SIG(&m->top))
        {
            break;
        }
    }

    /*
     * Process queued mbuf packets destined for TCP socket
     */
    if ((t & THREAD_RTWL) != 0)
    {
        while (!IS_SIG(&m->top) && (mi = mbuf_peek(m->mbuf)) != NULL)
        {
            multi_io_action(m, mi, TA_SOCKET_WRITE, true, f, t);
        }
    }
}

void *threaded_multi_io_process_io(void *a)
{
    /*
       dual mode notes:
         - thread1 handles tunn-read--->---link-send && thread2 handles link-read--->---tunn-send
         - assign thread1 to handle the pre_select() call as it falls under the threaded paths
           and the function will eventually overwrite the c2.buf and c2.to_link buffer variables
           which will then cause data conflict and corruption errors if not called from thread1
         - the server is slower to move through the key session states than the client is
           so hold old keys longer before rotate and delay using new keys before selection
         - dual mode is based on the organization and separation work implemented in bulk mode
    */
    struct dual_args *d = (struct dual_args *)a;
    struct thread_pointer *b = d->b;
    int t = d->t;
    unsigned int f = d->f;
    uint8_t buff[5];
    size_t leng;
    while (true)
    {
        if (b->p->z != 1) { break; }
        leng = read(d->w[0][0], buff, 1);
        if (leng < 1) { /* no-op */ }
        if (b->p->z != 1) { break; }
        struct multi_context *m = b->p->m[b->i-1];
        if (d->a == TA_UNDEF)
        {
            multi_io_process_io(b, f, t);
        }
        else
        {
            multi_io_action(m, NULL, TA_TIMEOUT, false, f, t);
        }
        d->z = 0;
        leng = write(d->w[1][1], buff, 1);
    }
    return NULL;
}

void
multi_io_action(struct multi_context *m, struct multi_instance *mi, int action, bool poll, const unsigned int flags, int t)
{
    do
    {
        msg(D_MULTI_DEBUG, "MULTI IO: multi_io_action t=%d a=%s p=%d", t, pract(action), poll);

        if ((t == THREAD_RTWL) && !(action == TA_TIMEOUT || action == TA_INITIAL
                                    || action == TA_TUN_READ || action == TA_INST_LENG
                                    || action == TA_SOCKET_WRITE))
        {
            return;
        }

        if ((t == THREAD_RLWT) && !(action == TA_TIMEOUT
                                    || action == TA_SOCKET_READ || action == TA_SOCKET_READ_RESIDUAL
                                    || action == TA_TUN_WRITE))
        {
            return;
        }


        /*
         * Dispatch the action
         */
        multi_io_dispatch(m, mi, action, flags);

        /*
         * Signal received or connection
         * reset by peer?
         */
        if (mi && IS_SIG(&mi->context))
        {
            multi_close_instance_on_signal(m, mi);
            break;
        }
        if (m->pending && IS_SIG(&m->pending->context))
        {
            multi_close_instance_on_signal(m, m->pending);
            break;
        }
        if (m->pending2 && IS_SIG(&m->pending2->context))
        {
            multi_close_instance_on_signal(m, m->pending2);
            break;
        }


        /*
         * If dispatch produced any pending output
         * for a particular instance, point to
         * that instance.
         */
        int retry_undef = 0;
        if (t == THREAD_RTWL)
        {
            if (m->pending)
            {
                mi = m->pending;
            }
        }
        if (t == THREAD_RLWT)
        {
            if (m->pending2)
            {
                mi = m->pending2;
            }
        }
        if (t == THREAD_MAIN)
        {
            if (m->pending)
            {
                mi = m->pending;
            }
            if (m->pending2)
            {
                if (!m->pending)
                {
                    mi = m->pending2;
                }
                else
                {
                    retry_undef = 1;
                }
            }
        }


        /*
         * Based on the effects of the action,
         * such as generating pending output,
         * possibly transition to a new action state.
         */
        action = multi_io_post(m, mi, action, t);
        if ((action == TA_UNDEF) && (retry_undef == 1))
        {
            mi = m->pending2;
            action = multi_io_post(m, mi, action, t);
        }
        /*if (action == TA_UNDEF)
        {
            mi = look_left(m);
            if (mi)
            {
                multi_set_pending2(m, mi);
                action = TA_SOCKET_READ_RESIDUAL;
            }
        }*/


        poll = true;

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
