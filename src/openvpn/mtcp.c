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

#include "multi.h"
#include "forward.h"
#include "mtcp.h"
#include "multi_io.h"

#include "memdbg.h"

#ifdef HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#endif

struct ta_iow_flags
{
    unsigned int flags;
    unsigned int ret;
    unsigned int tun;
    unsigned int sock;
};

struct multi_instance *
multi_create_instance_tcp(struct multi_context *m, struct link_socket *sock)
{
    struct gc_arena gc = gc_new();
    struct multi_instance *mi = NULL;
    struct hash *hash = m->hash;

    mi = multi_create_instance(m, NULL, sock);
    if (mi)
    {
        mi->real.proto = sock->info.proto;
        struct hash_element *he;
        const uint32_t hv = hash_value(hash, &mi->real);
        struct hash_bucket *bucket = hash_bucket(hash, hv);

        multi_assign_peer_id(m, mi);

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

    ASSERT(mi->context.c2.link_sockets);
    ASSERT(mi->context.c2.link_sockets[0]);
    ASSERT(mi->context.c2.link_sockets[0]->info.lsa);
    ASSERT(mi->context.c2.link_sockets[0]->mode == LS_MODE_TCP_ACCEPT_FROM);
    ASSERT(mi->context.c2.link_sockets[0]->info.lsa->actual.dest.addr.sa.sa_family == AF_INET
           || mi->context.c2.link_sockets[0]->info.lsa->actual.dest.addr.sa.sa_family == AF_INET6
           );
    mi->real.proto = mi->context.c2.link_sockets[0]->info.proto;
    if (!mroute_extract_openvpn_sockaddr(&mi->real,
                                         &mi->context.c2.link_sockets[0]->info.lsa->actual.dest,
                                         true))
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

void
multi_tcp_delete_event(struct multi_io *multi_io, event_t event)
{
    if (multi_io && multi_io->es)
    {
        event_del(multi_io->es, event);
    }
}

void
multi_tcp_dereference_instance(struct multi_io *multi_io, struct multi_instance *mi)
{
    struct link_socket *sock = mi->context.c2.link_sockets[0];
    if (sock && mi->socket_set_called)
    {
        event_del(multi_io->es, socket_event_handle(sock));
        mi->socket_set_called = false;
    }
    multi_io->n_esr = 0;
}

bool
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

bool
multi_tcp_process_outgoing_link(struct multi_context *m, bool defer, const unsigned int mpp_flags)
{
    struct multi_instance *mi = multi_process_outgoing_link_pre(m);
    bool ret = true;

    if (mi)
    {
        if ((defer && !proto_is_dgram(mi->context.c2.link_sockets[0]->info.proto))
            || mbuf_defined(mi->tcp_link_out_deferred))
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
