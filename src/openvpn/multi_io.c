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

        case TA_INITIAL:
            return "TA_INITIAL";

        case TA_TIMEOUT:
            return "TA_TIMEOUT";

        case TA_LINK_PROC:
            return "TA_LINK_PROC";

        case TA_LINK_READ:
            return "TA_LINK_READ";

        case TA_LINK_WRITE:
            return "TA_LINK_WRITE";

        case TA_INTF_PROC:
            return "TA_INTF_PROC";

        case TA_INTF_READ:
            return "TA_INTF_READ";

        case TA_INTF_WRITE:
            return "TA_INTF_WRITE";

        case TA_INST_LENG:
            return "TA_INST_LENG";

        case TA_FORWARD:
            return "TA_FORWARD";

        case TA_KEYS:
            return "TA_KEYS";

        default:
            return "TA_????";
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
    }
}

int look_link(struct multi_context *m)
{
    for (int x = 0; x < m->max_clients; ++x)
    {
        struct multi_instance *i = m->instances[x];
        struct context *c = multi_get_context(m, i);
        if (!i) { continue; }
        if (TUN_IN(c))
        {
            multi_set_pending(m, i);
            return TA_INTF_PROC;
        }
        if (LINK_OUT(c))
        {
            multi_set_pending(m, i);
            return TA_LINK_WRITE;
        }
        if (REKEY_OUT(c))
        {
            multi_set_pending(m, i);
            return TA_KEYS;
        }
    }
    return TA_UNDEF;
}

int look_intf(struct multi_context *m)
{
    for (int x = 0; x < m->max_clients; ++x)
    {
        struct multi_instance *i = m->instances[x];
        struct context *c = multi_get_context(m, i);
        if (!i) { continue; }
        if (LINK_IN(c))
        {
            multi_set_pending2(m, i);
            return TA_LINK_PROC;
        }
        if (TUN_OUT(c))
        {
            multi_set_pending2(m, i);
            return TA_INTF_WRITE;
        }
    }
    return TA_UNDEF;
}

int look_left(struct multi_context *m)
{
    for (int x = 0; x < m->max_clients; ++x)
    {
        struct multi_instance *i = m->instances[x];
        if (!i) { continue; }
        if (LINK_LEFT(i))
        {
            multi_set_pending2(m, i);
            return TA_LINK_READ;
        }
    }
    return TA_UNDEF;
}

int multi_io_wait(struct multi_context *m)
{
    int status;
    struct multi_io *multi_io = &(m->multi_io[THREAD_MAIN]);
    unsigned int *persistent = &multi_io->tun_rwflags;

    for (int i = 0; i < m->top.c1.link_sockets_num; ++i)
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

    status = event_wait(multi_io->es, &m->top.c2.timeval, multi_io->esr, multi_io->maxevents);
    update_time();
    multi_io->n_esr = (status > 0) ? status : 0;
    return status;
}

int multi_io_instance(struct multi_context *m, const int action, const unsigned int add_flags, int t)
{
    const unsigned int mpp_flags = MPP_PRE_SELECT | MPP_RECORD_TOUCH | add_flags;

    bool pall = false;
    time_t secs = time(NULL);

    if ((secs - m->last[t]) >= POST_WAIT)
    {
        pall = true;
    }

    if (pall || m->post[t])
    {
        for (int x = 0; x < m->max_clients; ++x)
        {
            struct multi_instance *i = m->instances[x];

            if (!i) { continue; }

            if (i && IS_SIG(&i->context))
            {
                multi_close_instance_on_signal(m, i);
                continue;
            }

            if (pall || i->post[t])
            {
                set_prefix(i);
                multi_process_post(m, i, mpp_flags);
                clear_prefix();

                i->post[t] = false;
                if (pall) { i->last[t] = secs; }
            }
        }

        m->post[t] = false;
        if (pall) { m->last[t] = secs; }
    }

    return action;
}

int multi_io_dispatch(struct multi_context *m, const int action, const unsigned int add_flags, int t)
{
    const unsigned int mpp_flags = MPP_PRE_SELECT | MPP_RECORD_TOUCH | add_flags;

    struct multi_instance *i = m->pending;

    dmsg(D_MULTI_DEBUG, "MULTI IO: multi_io_dispatch a=%s m=" ptr_format, pract(action), (ptr_type)m);

    switch (action)
    {
        case TA_INTF_PROC:
            multi_process_incoming_intf(m, mpp_flags | MPP_EVENT_PROC, t);
            break;

        case TA_KEYS:
        case TA_LINK_WRITE:
            multi_process_outgoing_link(m, mpp_flags, t);
            break;

        case TA_INST_LENG:
        case TA_INTF_READ:
            threaded_multi_inp_intf(m, mpp_flags, t);
            break;

        case TA_LINK_PROC:
            multi_process_incoming_link(m, mpp_flags | MPP_EVENT_PROC, t);
            break;

        case TA_INTF_WRITE:
            multi_process_outgoing_intf(m, mpp_flags, t);
            break;

        case TA_LINK_READ:
            multi_process_incoming_link(m, mpp_flags, t);
            break;

        case TA_INITIAL:
            if (i)
            {
                i->post[t] = true;
                m->post[t] = true;
            }
            break;

        case TA_TIMEOUT:
            multi_process_timeout(m, mpp_flags, t);
            break;

        default:
            msg(M_FATAL, "MULTI IO: multi_io_dispatch, unhandled action=%d", action);
    }

    return action;
}

int multi_io_pending(struct multi_context *m, const int action, const unsigned int add_flags, int t)
{
    int newaction = TA_UNDEF;
    int getaction = TA_UNDEF;

    if ((t & THREAD_RTWL) != 0)
    {
        if ((getaction = look_link(m)) != TA_UNDEF)
        {
            newaction = getaction;
            goto last;
        }
        else if (INST_LENG(m))
        {
            newaction = TA_INST_LENG;
            goto last;
        }
    }

    if ((t & THREAD_RLWT) != 0)
    {
        if ((getaction = look_intf(m)) != TA_UNDEF)
        {
            newaction = getaction;
            goto last;
        }
        else if ((getaction = look_left(m)) != TA_UNDEF)
        {
            newaction = getaction;
            goto last;
        }
    }

last:
    dmsg(D_MULTI_DEBUG, "MULTI IO: multi_io_post %s -> %s", pract(action), pract(newaction));

    return newaction;
}

void multi_io_action(struct multi_context *m, int action, bool poll, const unsigned int flags, int t)
{
    do
    {
        msg(D_MULTI_DEBUG, "MULTI IO: multi_io_action t=%d a=%s p=%d", t, pract(action), poll);

        if ((t == THREAD_RTWL) && !(action == TA_TIMEOUT || action == TA_INITIAL || action == TA_INTF_READ || action == TA_INST_LENG || action == TA_INTF_PROC || action == TA_LINK_WRITE || action == TA_KEYS))
        {
            break;
        }

        if ((t == THREAD_RLWT) && !(action == TA_TIMEOUT || action == TA_LINK_READ || action == TA_LINK_PROC || action == TA_INTF_WRITE))
        {
            break;
        }


        /*
         * Dispatch the action
         */
        action = multi_io_dispatch(m, action, flags, t);

        /*
         * Process any instances
         */
        action = multi_io_instance(m, action, flags, t);

        /*
         * Process any pending
         */
        action = multi_io_pending(m, action, flags, t);


        poll = true;

    } while (action != TA_UNDEF);
}

void multi_io_process_io(struct thread_pointer *b, const unsigned int f, int t)
{
    struct multi_context *m = b->p->m[b->i-1];
    struct multi_io *multi_io = &(m->multi_io[t]);
    struct multi_instance *mi;
    int getaction;

    while ((getaction = multi_io_pending(m, TA_UNDEF, f, t)) != TA_UNDEF)
    {
        multi_io_action(m, getaction, false, f, t);
    }

    for (int i = 0; i < multi_io->n_esr; ++i)
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
                if ((t & THREAD_RLWT) != 0)
                {
                    if (e->rwflags & EVENT_READ)
                    {
                        if (IS_SIG(&mi->context) || (!LINK_SOCK(mi)))
                        {
                            multi_close_instance_on_signal(m, mi);
                        }
                        else
                        {
                            multi_set_pending2(m, mi);
                            multi_io_action(m, TA_LINK_READ, false, f, t);
                        }
                    }
                }
            }

            /* new incoming TCP client attempting to connect? */
            if (ev_arg->type == EVENT_ARG_LINK_SOCKET)
            {
                if ((t & THREAD_RTWL) != 0)
                {
                    ASSERT(ev_arg->u.sock);
                    if (!proto_is_dgram(ev_arg->u.sock->info.proto))
                    {
                        socket_reset_listen_persistent(ev_arg->u.sock);
                        mi = multi_create_instance_tcp(b, ev_arg->u.sock);
                        multi_set_pending(m, mi);
                        multi_io_action(b->p->p, TA_INITIAL, false, f, t);
                    }
                    else
                    {
                        multi_process_io_udp(m, ev_arg->u.sock, t);
                        multi_io_action(m, TA_INITIAL, false, f, t);
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
                    if ((t & THREAD_RTWL) != 0)
                    {
                        if (e->rwflags & EVENT_READ)
                        {
                            multi_io_action(m, TA_INTF_READ, false, f, t);
                        }
                    }
                }
#if defined(ENABLE_DCO)
                /* incoming data on DCO? */
                if (e->arg == MULTI_IO_DCO)
                {
                    if (t == THREAD_MAIN)
                    {
                        dco_read_and_process(&m->top.c1.tuntap->dco);
                    }
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
        }
        if (IS_SIG(&m->top))
        {
            break;
        }
    }

    if ((t & THREAD_RTWL) != 0)
    {
        if (m->mtio_stat == 3)
        {
            for (int x = 0; x < m->max_clients; ++x)
            {
                struct multi_instance *i = m->instances[x];
                if (!i) { continue; }
                if (LINK_SOCK(i) && (i->mtio_stat == 3))
                {
                    multi_context_switch_addr(m, i, true, true);
                    i->mtio_stat = 5;
                    m->mtio_stat = 5;
                }
            }
        }
    }
}

void
multi_io_delete_event(struct multi_io *multi_io, event_t event)
{
    if (multi_io && multi_io->es)
    {
        event_del(multi_io->es, event);
    }
}
