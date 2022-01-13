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

#include "multi.h"
#include "forward.h"

#include "memdbg.h"

#ifdef HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#endif

/*
 * TCP States
 */
#define TA_UNDEF                 0
#define TA_SOCKET_READ           1
#define TA_SOCKET_READ_RESIDUAL  2
#define TA_SOCKET_WRITE          3
#define TA_SOCKET_WRITE_READY    4
#define TA_SOCKET_WRITE_DEFERRED 5
#define TA_TUN_READ              6
#define TA_TUN_WRITE             7
#define TA_INITIAL               8
#define TA_TIMEOUT               9
#define TA_TUN_WRITE_TIMEOUT     10

/*
 * Special tags passed to event.[ch] functions
 */
#define MTCP_SOCKET      ((void *)1)
#define MTCP_TUN         ((void *)2)
#define MTCP_SIG         ((void *)3) /* Only on Windows */
#define MTCP_MANAGEMENT ((void *)4)
#define MTCP_FILE_CLOSE_WRITE ((void *)5)
#define MTCP_DCO        ((void *)6)

#define MTCP_N           ((void *)16) /* upper bound on MTCP_x */

struct ta_iow_flags
{
    unsigned int flags;
    unsigned int ret;
    unsigned int tun;
    unsigned int sock;
};

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

static struct multi_instance *
multi_create_instance_tcp(struct multi_context *m)
{
    struct gc_arena gc = gc_new();
    struct multi_instance *mi = NULL;
    struct hash *hash = m->hash;

    mi = multi_create_instance(m, NULL);
    multi_assign_peer_id(m, mi);

    if (mi)
    {
        struct hash_element *he;
        const uint32_t hv = hash_value(hash, &mi->real);
        struct hash_bucket *bucket = hash_bucket(hash, hv);

        he = hash_lookup_fast(hash, bucket, &mi->real, hv);

        if (he)
        {
            struct multi_instance *oldmi = (struct multi_instance *) he->value;
            msg(D_MULTI_LOW, "MULTI TCP: new incoming client address matches existing client address -- new client takes precedence");
            oldmi->did_real_hash = false;
            multi_close_instance(m, oldmi, false);
            he->key = &mi->real;
            he->value = mi;
        }
        else
        {
            hash_add_fast(hash, bucket, &mi->real, hv, mi);
        }

        mi->did_real_hash = true;
    }

#ifdef ENABLE_DEBUG
    if (mi)
    {
        dmsg(D_MULTI_DEBUG, "MULTI TCP: instance added: %s", mroute_addr_print(&mi->real, &gc));
    }
    else
    {
        dmsg(D_MULTI_DEBUG, "MULTI TCP: new client instance failed");
    }
#endif

    gc_free(&gc);
    ASSERT(!(mi && mi->halt));
    return mi;
}

bool
multi_tcp_instance_specific_init(struct multi_context *m, struct multi_instance *mi)
{
    /* buffer for queued TCP socket output packets */
    mi->tcp_link_out_deferred = mbuf_init(m->top.options.n_bcast_buf);

    ASSERT(mi->context.c2.link_socket);
    ASSERT(mi->context.c2.link_socket->info.lsa);
    ASSERT(mi->context.c2.link_socket->mode == LS_MODE_TCP_ACCEPT_FROM);
    ASSERT(mi->context.c2.link_socket->info.lsa->actual.dest.addr.sa.sa_family == AF_INET
           || mi->context.c2.link_socket->info.lsa->actual.dest.addr.sa.sa_family == AF_INET6
           );
    if (!mroute_extract_openvpn_sockaddr(&mi->real, &mi->context.c2.link_socket->info.lsa->actual.dest, true))
    {
        msg(D_MULTI_ERRORS, "MULTI TCP: TCP client address is undefined");
        return false;
    }
    return true;
}

void
multi_tcp_instance_specific_free(struct multi_instance *mi)
{
    mbuf_free(mi->tcp_link_out_deferred);
}

struct multi_tcp *
multi_tcp_init(int maxevents, int *maxclients)
{
    struct multi_tcp *mtcp;
    const int extra_events = BASE_N_EVENTS;

    ASSERT(maxevents >= 1);
    ASSERT(maxclients);

    ALLOC_OBJ_CLEAR(mtcp, struct multi_tcp);
    mtcp->maxevents = maxevents + extra_events;
    mtcp->es = event_set_init(&mtcp->maxevents, 0);
    wait_signal(mtcp->es, MTCP_SIG);
    ALLOC_ARRAY(mtcp->esr, struct event_set_return, mtcp->maxevents);
    *maxclients = max_int(min_int(mtcp->maxevents - extra_events, *maxclients), 1);
    msg(D_MULTI_LOW, "MULTI: TCP INIT maxclients=%d maxevents=%d", *maxclients, mtcp->maxevents);
    return mtcp;
}

void
multi_tcp_delete_event(struct multi_tcp *mtcp, event_t event)
{
    if (mtcp && mtcp->es)
    {
        event_del(mtcp->es, event);
    }
}

void
multi_tcp_free(struct multi_tcp *mtcp)
{
    if (mtcp)
    {
        event_free(mtcp->es);
        free(mtcp->esr);
        free(mtcp);
    }
}

void
multi_tcp_dereference_instance(struct multi_tcp *mtcp, struct multi_instance *mi)
{
    struct link_socket *ls = mi->context.c2.link_socket;
    if (ls && mi->socket_set_called)
    {
        event_del(mtcp->es, socket_event_handle(ls));
        mi->socket_set_called = false;
    }
    mtcp->n_esr = 0;
}

static inline void
multi_tcp_set_global_rw_flags(struct multi_context *m, struct multi_instance *mi)
{
    if (mi)
    {
        mi->socket_set_called = true;
        socket_set(mi->context.c2.link_socket,
                   m->mtcp->es,
                   mbuf_defined(mi->tcp_link_out_deferred) ? EVENT_WRITE : EVENT_READ,
                   mi,
                   &mi->tcp_rwflags);
    }
}

static inline int
multi_tcp_wait(const struct context *c,
               struct multi_tcp *mtcp)
{
    int status;
    unsigned int *persistent = &mtcp->tun_rwflags;
    socket_set_listen_persistent(c->c2.link_socket, mtcp->es, MTCP_SOCKET);

#ifdef _WIN32
    if (tuntap_is_wintun(c->c1.tuntap))
    {
        if (!tuntap_ring_empty(c->c1.tuntap))
        {
            /* there is data in wintun ring buffer, read it immediately */
            mtcp->esr[0].arg = MTCP_TUN;
            mtcp->esr[0].rwflags = EVENT_READ;
            mtcp->n_esr = 1;
            return 1;
        }
        persistent = NULL;
    }
#endif
    tun_set(c->c1.tuntap, mtcp->es, EVENT_READ, MTCP_TUN, persistent);
#if defined(TARGET_LINUX)
    dco_event_set(&c->c1.tuntap->dco, mtcp->es, MTCP_DCO);
#endif

#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_socket_set(management, mtcp->es, MTCP_MANAGEMENT, &mtcp->management_persist_flags);
    }
#endif

#ifdef ENABLE_ASYNC_PUSH
    /* arm inotify watcher */
    event_ctl(mtcp->es, c->c2.inotify_fd, EVENT_READ, MTCP_FILE_CLOSE_WRITE);
#endif

    status = event_wait(mtcp->es, &c->c2.timeval, mtcp->esr, mtcp->maxevents);
    update_time();
    mtcp->n_esr = 0;
    if (status > 0)
    {
        mtcp->n_esr = status;
    }
    return status;
}

static inline struct context *
multi_tcp_context(struct multi_context *m, struct multi_instance *mi)
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

static bool
multi_tcp_process_outgoing_link_ready(struct multi_context *m, struct multi_instance *mi, const unsigned int mpp_flags)
{
    struct mbuf_item item;
    bool ret = true;
    ASSERT(mi);

    /* extract from queue */
    if (mbuf_extract_item(mi->tcp_link_out_deferred, &item)) /* ciphertext IP packet */
    {
        dmsg(D_MULTI_TCP, "MULTI TCP: transmitting previously deferred packet");

        ASSERT(mi == item.instance);
        mi->context.c2.to_link = item.buffer->buf;
        ret = multi_process_outgoing_link_dowork(m, mi, mpp_flags);
        if (!ret)
        {
            mi = NULL;
        }
        mbuf_free_buf(item.buffer);
    }
    return ret;
}

static bool
multi_tcp_process_outgoing_link(struct multi_context *m, bool defer, const unsigned int mpp_flags)
{
    struct multi_instance *mi = multi_process_outgoing_link_pre(m);
    bool ret = true;

    if (mi)
    {
        if (defer || mbuf_defined(mi->tcp_link_out_deferred))
        {
            /* save to queue */
            struct buffer *buf = &mi->context.c2.to_link;
            if (BLEN(buf) > 0)
            {
                struct mbuf_buffer *mb = mbuf_alloc_buf(buf);
                struct mbuf_item item;

                set_prefix(mi);
                dmsg(D_MULTI_TCP, "MULTI TCP: queuing deferred packet");
                item.buffer = mb;
                item.instance = mi;
                mbuf_add_item(mi->tcp_link_out_deferred, &item);
                mbuf_free_buf(mb);
                buf_reset(buf);
                ret = multi_process_post(m, mi, mpp_flags);
                if (!ret)
                {
                    mi = NULL;
                }
                clear_prefix();
            }
        }
        else
        {
            ret = multi_process_outgoing_link_dowork(m, mi, mpp_flags);
            if (!ret)
            {
                mi = NULL;
            }
        }
    }
    return ret;
}

static int
multi_tcp_wait_lite(struct multi_context *m, struct multi_instance *mi, const int action, bool *tun_input_pending)
{
    struct context *c = multi_tcp_context(m, mi);
    unsigned int looking_for = 0;

    dmsg(D_MULTI_DEBUG, "MULTI TCP: multi_tcp_wait_lite a=%s mi=" ptr_format,
         pract(action),
         (ptr_type)mi);

    tv_clear(&c->c2.timeval); /* ZERO-TIMEOUT */

#if defined(TARGET_LINUX)
    if (mi && mi->context.c2.link_socket->info.dco_installed)
    {
        /* If we got a socket that has been handed over to the kernel
         * we must not call the normal socket function to figure out
         * if it is readable or writable */
        /* Assert that we only have the DCO exptected flags */
        ASSERT(action & (TA_SOCKET_READ | TA_SOCKET_WRITE));

        /* We are always ready! */
        return action;
    }
#endif

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
            msg(M_FATAL, "MULTI TCP: multi_tcp_wait_lite, unhandled action=%d", action);
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
            /* TCP socket output buffer is full */
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
multi_tcp_dispatch(struct multi_context *m, struct multi_instance *mi, const int action)
{
    const unsigned int mpp_flags = MPP_PRE_SELECT|MPP_RECORD_TOUCH;
    struct multi_instance *touched = mi;
    m->mpp_touched = &touched;

    dmsg(D_MULTI_DEBUG, "MULTI TCP: multi_tcp_dispatch a=%s mi=" ptr_format,
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
            ASSERT(mi->context.c2.link_socket);
            set_prefix(mi);
            read_incoming_link(&mi->context);
            clear_prefix();
            if (!IS_SIG(&mi->context))
            {
                multi_process_incoming_link(m, mi, mpp_flags);
                if (!IS_SIG(&mi->context))
                {
                    stream_buf_read_setup(mi->context.c2.link_socket);
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
            if (!mi->context.c2.link_socket->info.dco_installed)
            {
                multi_tcp_set_global_rw_flags(m, mi);
            }
            multi_process_post(m, mi, mpp_flags);
            break;

        default:
            msg(M_FATAL, "MULTI TCP: multi_tcp_dispatch, unhandled action=%d", action);
    }

    m->mpp_touched = NULL;
    return touched;
}

static int
multi_tcp_post(struct multi_context *m, struct multi_instance *mi, const int action)
{
    struct context *c = multi_tcp_context(m, mi);
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
            if (mi && socket_read_residual(c->c2.link_socket))
            {
                newaction = TA_SOCKET_READ_RESIDUAL;
            }
            else
            {
                if (!c->c2.link_socket->info.dco_installed)
                {
                    multi_tcp_set_global_rw_flags(m, mi);
                }
            }
            break;

        default:
        {
            struct gc_arena gc = gc_new();
            msg(M_FATAL, "MULTI TCP: multi_tcp_post bad state, mi=%s flags=%d",
                multi_instance_string(mi, false, &gc),
                flags);
            gc_free(&gc);
            break;
        }
    }

    dmsg(D_MULTI_DEBUG, "MULTI TCP: multi_tcp_post %s -> %s",
         pract(action),
         pract(newaction));

    return newaction;
}

static void
multi_tcp_action(struct multi_context *m, struct multi_instance *mi, int action, bool poll)
{
    bool tun_input_pending = false;

    do
    {
        dmsg(D_MULTI_DEBUG, "MULTI TCP: multi_tcp_action a=%s p=%d",
             pract(action),
             poll);

        /*
         * If TA_SOCKET_READ_RESIDUAL, it means we still have pending
         * input packets which were read by a prior TCP recv.
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
            action = multi_tcp_wait_lite(m, mi, action, &tun_input_pending);
            if (action == TA_UNDEF)
            {
                msg(M_FATAL, "MULTI TCP: I/O wait required blocking in multi_tcp_action, action=%d", orig_action);
            }
        }

        /*
         * Dispatch the action
         */
        struct multi_instance *touched = multi_tcp_dispatch(m, mi, action);

        /*
         * Signal received or TCP connection
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
        action = multi_tcp_post(m, mi, action);

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

static void
multi_tcp_process_io(struct multi_context *m)
{
    struct multi_tcp *mtcp = m->mtcp;
    int i;

    for (i = 0; i < mtcp->n_esr; ++i)
    {
        struct event_set_return *e = &mtcp->esr[i];

        /* incoming data for instance? */
        if (e->arg >= MTCP_N)
        {
            struct multi_instance *mi = (struct multi_instance *) e->arg;
            if (mi)
            {
                if (e->rwflags & EVENT_WRITE)
                {
                    multi_tcp_action(m, mi, TA_SOCKET_WRITE_READY, false);
                }
                else if (e->rwflags & EVENT_READ)
                {
                    multi_tcp_action(m, mi, TA_SOCKET_READ, false);
                }
            }
        }
        else
        {
#ifdef ENABLE_MANAGEMENT
            if (e->arg == MTCP_MANAGEMENT)
            {
                ASSERT(management);
                management_io(management);
            }
            else
#endif
            /* incoming data on TUN? */
            if (e->arg == MTCP_TUN)
            {
                if (e->rwflags & EVENT_WRITE)
                {
                    multi_tcp_action(m, NULL, TA_TUN_WRITE, false);
                }
                else if (e->rwflags & EVENT_READ)
                {
                    multi_tcp_action(m, NULL, TA_TUN_READ, false);
                }
            }
            /* new incoming TCP client attempting to connect? */
            else if (e->arg == MTCP_SOCKET)
            {
                struct multi_instance *mi;
                ASSERT(m->top.c2.link_socket);
                socket_reset_listen_persistent(m->top.c2.link_socket);
                mi = multi_create_instance_tcp(m);
                if (mi)
                {
                    multi_tcp_action(m, mi, TA_INITIAL, false);
                }
            }
#if defined(ENABLE_DCO) && defined(TARGET_LINUX)
            /* incoming data on DCO? */
            else if (e->arg == MTCP_DCO)
            {
                multi_process_incoming_dco(m);
            }
#endif
            /* signal received? */
            else if (e->arg == MTCP_SIG)
            {
                get_signal(&m->top.sig->signal_received);
            }
#ifdef ENABLE_ASYNC_PUSH
            else if (e->arg == MTCP_FILE_CLOSE_WRITE)
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
    mtcp->n_esr = 0;

    /*
     * Process queued mbuf packets destined for TCP socket
     */
    {
        struct multi_instance *mi;
        while (!IS_SIG(&m->top) && (mi = mbuf_peek(m->mbuf)) != NULL)
        {
            multi_tcp_action(m, mi, TA_SOCKET_WRITE, true);
        }
    }
}

/*
 * Top level event loop for single-threaded operation.
 * TCP mode.
 */
void
tunnel_server_tcp(struct context *top)
{
    struct multi_context multi;
    int status;

    top->mode = CM_TOP;
    context_clear_2(top);

    /* initialize top-tunnel instance */
    init_instance_handle_signals(top, top->es, CC_HARD_USR1_TO_HUP);
    if (IS_SIG(top))
    {
        return;
    }

    /* initialize global multi_context object */
    multi_init(&multi, top, true);

    /* initialize our cloned top object */
    multi_top_init(&multi, top);

    /* initialize management interface */
    init_management_callback_multi(&multi);

    /* finished with initialization */
    initialization_sequence_completed(top, ISC_SERVER); /* --mode server --proto tcp-server */

#ifdef ENABLE_ASYNC_PUSH
    multi.top.c2.inotify_fd = inotify_init();
    if (multi.top.c2.inotify_fd < 0)
    {
        msg(D_MULTI_ERRORS | M_ERRNO, "MULTI: inotify_init error");
    }
#endif

    /* per-packet event loop */
    while (true)
    {
        perf_push(PERF_EVENT_LOOP);

        /* wait on tun/socket list */
        multi_get_timeout(&multi, &multi.top.c2.timeval);
        status = multi_tcp_wait(&multi.top, multi.mtcp);
        MULTI_CHECK_SIG(&multi);

        /* check on status of coarse timers */
        multi_process_per_second_timers(&multi);

        /* timeout? */
        if (status > 0)
        {
            /* process the I/O which triggered select */
            multi_tcp_process_io(&multi);
            MULTI_CHECK_SIG(&multi);
        }
        else if (status == 0)
        {
            multi_tcp_action(&multi, NULL, TA_TIMEOUT, false);
        }

        perf_pop();
    }

#ifdef ENABLE_ASYNC_PUSH
    close(top->c2.inotify_fd);
#endif

    /* shut down management interface */
    uninit_management_callback();

    /* save ifconfig-pool */
    multi_ifconfig_pool_persist(&multi, true);

    /* tear down tunnel instance (unless --persist-tun) */
    multi_uninit(&multi);
    multi_top_free(&multi);
    close_instance(top);
}
