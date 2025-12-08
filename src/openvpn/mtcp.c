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
multi_create_instance_tcp(struct thread_pointer *b, struct link_socket *sock)
{
    struct gc_arena gc = gc_new();
    struct multi_context *m = b->p->m[b->i-1];
    struct multi_instance *mi = NULL;
    struct hash *hash = m->hash;

    mi = multi_create_instance(b, NULL, sock);
    if (mi)
    {
        m = b->p->p;
        hash = m->hash;
        mi->real.proto = sock->info.proto;
        struct hash_element *he;
        const uint32_t hv = hash_value(hash, &mi->real);
        struct hash_bucket *bucket = hash_bucket(hash, hv);

        multi_assign_peer_id(m, mi);

        he = hash_lookup_fast(hash, bucket, &mi->real, hv);

        if (he)
        {
            struct multi_instance *oldmi = (struct multi_instance *)he->value;
            msg(D_MULTI_LOW,
                "MULTI TCP: new incoming client address matches existing client address -- new client takes precedence");
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
    ASSERT(mi->context.c2.link_sockets);
    ASSERT(mi->context.c2.link_sockets[0]);
    ASSERT(mi->context.c2.link_sockets[0]->info.lsa);
    ASSERT(mi->context.c2.link_sockets[0]->mode == LS_MODE_TCP_ACCEPT_FROM);
    ASSERT(mi->context.c2.link_sockets[0]->info.lsa->actual.dest.addr.sa.sa_family == AF_INET
           || mi->context.c2.link_sockets[0]->info.lsa->actual.dest.addr.sa.sa_family == AF_INET6);
    mi->real.proto = mi->context.c2.link_sockets[0]->info.proto;
    if (!mroute_extract_openvpn_sockaddr(
            &mi->real, &mi->context.c2.link_sockets[0]->info.lsa->actual.dest, true))
    {
        msg(D_MULTI_ERRORS, "MULTI TCP: TCP client address is undefined");
        return false;
    }
    return true;
}

void
multi_tcp_instance_specific_free(struct multi_instance *mi)
{
    /* no-op */
}

void
multi_tcp_delete_event(struct multi_io *multi_io, event_t event)
{
    if (multi_io && multi_io->es)
    {
        event_del(multi_io->es, event);
    }
}
