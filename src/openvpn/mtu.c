/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
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

#include "common.h"
#include "buffer.h"
#include "error.h"
#include "integer.h"
#include "mtu.h"
#include "options.h"

#include "memdbg.h"

/* allocate a buffer for socket or tun layer */
void
alloc_buf_sock_tun(struct buffer *buf,
                   const struct frame *frame,
                   const bool tuntap_buffer,
                   const unsigned int align_mask)
{
    /* allocate buffer for overlapped I/O */
    *buf = alloc_buf(BUF_SIZE(frame));
    ASSERT(buf_init(buf, FRAME_HEADROOM_ADJ(frame, align_mask)));
    buf->len = tuntap_buffer ? MAX_RW_SIZE_TUN(frame) : MAX_RW_SIZE_LINK(frame);
    ASSERT(buf_safe(buf, 0));
}

void
frame_finalize(struct frame *frame,
               bool link_mtu_defined,
               int link_mtu,
               bool tun_mtu_defined,
               int tun_mtu)
{
    /* Set link_mtu based on command line options */
    if (tun_mtu_defined)
    {
        ASSERT(!link_mtu_defined);
        frame->link_mtu = tun_mtu + TUN_LINK_DELTA(frame);
    }
    else
    {
        ASSERT(link_mtu_defined);
        frame->link_mtu = link_mtu;
    }

    if (TUN_MTU_SIZE(frame) < TUN_MTU_MIN)
    {
        msg(M_WARN, "TUN MTU value (%d) must be at least %d", TUN_MTU_SIZE(frame), TUN_MTU_MIN);
        frame_print(frame, M_FATAL, "MTU is too small");
    }

    frame->link_mtu_dynamic = frame->link_mtu;
}

/*
 * Set the tun MTU dynamically.
 */
void
frame_set_mtu_dynamic(struct frame *frame, int mtu, unsigned int flags)
{

#ifdef ENABLE_DEBUG
    const int orig_mtu = mtu;
    const int orig_link_mtu_dynamic = frame->link_mtu_dynamic;
#endif

    ASSERT(mtu >= 0);

    if (flags & SET_MTU_TUN)
    {
        mtu += TUN_LINK_DELTA(frame);
    }

    if (!(flags & SET_MTU_UPPER_BOUND) || mtu < frame->link_mtu_dynamic)
    {
        frame->link_mtu_dynamic = constrain_int(
            mtu,
            EXPANDED_SIZE_MIN(frame),
            EXPANDED_SIZE(frame));
    }

    dmsg(D_MTU_DEBUG, "MTU DYNAMIC mtu=%d, flags=%u, %d -> %d",
         orig_mtu,
         flags,
         orig_link_mtu_dynamic,
         frame->link_mtu_dynamic);
}

/*
 * Move extra_frame octets into extra_tun.  Used by fragmenting code
 * to adjust frame relative to its position in the buffer processing
 * queue.
 */
void
frame_subtract_extra(struct frame *frame, const struct frame *src)
{
    frame->extra_frame -= src->extra_frame;
    frame->extra_tun   += src->extra_frame;
}

void
frame_init_mssfix(struct frame *frame, const struct options *options)
{
    if (options->ce.mssfix)
    {
        frame_set_mtu_dynamic(frame, options->ce.mssfix, SET_MTU_UPPER_BOUND);
    }
}

void
frame_print(const struct frame *frame,
            int level,
            const char *prefix)
{
    struct gc_arena gc = gc_new();
    struct buffer out = alloc_buf_gc(256, &gc);
    if (prefix)
    {
        buf_printf(&out, "%s ", prefix);
    }
    buf_printf(&out, "[");
    buf_printf(&out, " L:%d", frame->link_mtu);
    buf_printf(&out, " D:%d", frame->link_mtu_dynamic);
    buf_printf(&out, " EF:%d", frame->extra_frame);
    buf_printf(&out, " EB:%d", frame->extra_buffer);
    buf_printf(&out, " ET:%d", frame->extra_tun);
    buf_printf(&out, " EL:%d", frame->extra_link);
    if (frame->align_flags && frame->align_adjust)
    {
        buf_printf(&out, " AF:%u/%d", frame->align_flags, frame->align_adjust);
    }
    buf_printf(&out, " ]");

    msg(level, "%s", out.data);
    gc_free(&gc);
}

#define MTUDISC_NOT_SUPPORTED_MSG "--mtu-disc is not supported on this OS"

void
set_mtu_discover_type(int sd, int mtu_type, sa_family_t proto_af)
{
    if (mtu_type >= 0)
    {
        switch (proto_af)
        {
#if defined(HAVE_SETSOCKOPT) && defined(IP_MTU_DISCOVER)
            case AF_INET:
                if (setsockopt(sd, IPPROTO_IP, IP_MTU_DISCOVER,
                               (void *) &mtu_type, sizeof(mtu_type)))
                {
                    msg(M_ERR, "Error setting IP_MTU_DISCOVER type=%d on TCP/UDP socket",
                        mtu_type);
                }
                break;

#endif
#if defined(HAVE_SETSOCKOPT) && defined(IPV6_MTU_DISCOVER)
            case AF_INET6:
                if (setsockopt(sd, IPPROTO_IPV6, IPV6_MTU_DISCOVER,
                               (void *) &mtu_type, sizeof(mtu_type)))
                {
                    msg(M_ERR, "Error setting IPV6_MTU_DISCOVER type=%d on TCP6/UDP6 socket",
                        mtu_type);
                }
                break;

#endif
            default:
                msg(M_FATAL, MTUDISC_NOT_SUPPORTED_MSG);
                break;
        }
    }
}

int
translate_mtu_discover_type_name(const char *name)
{
#if defined(IP_PMTUDISC_DONT) && defined(IP_PMTUDISC_WANT) && defined(IP_PMTUDISC_DO)
    if (!strcmp(name, "yes"))
    {
        return IP_PMTUDISC_DO;
    }
    if (!strcmp(name, "maybe"))
    {
        return IP_PMTUDISC_WANT;
    }
    if (!strcmp(name, "no"))
    {
        return IP_PMTUDISC_DONT;
    }
    msg(M_FATAL,
        "invalid --mtu-disc type: '%s' -- valid types are 'yes', 'maybe', or 'no'",
        name);
#else  /* if defined(IP_PMTUDISC_DONT) && defined(IP_PMTUDISC_WANT) && defined(IP_PMTUDISC_DO) */
    msg(M_FATAL, MTUDISC_NOT_SUPPORTED_MSG);
#endif
    return -1;                  /* NOTREACHED */
}

#if EXTENDED_SOCKET_ERROR_CAPABILITY

struct probehdr
{
    uint32_t ttl;
    struct timeval tv;
};

const char *
format_extended_socket_error(int fd, int *mtu, struct gc_arena *gc)
{
    int res;
    struct probehdr rcvbuf;
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct sock_extended_err *e;
    struct sockaddr_in addr;
    struct buffer out = alloc_buf_gc(256, gc);
    char *cbuf = (char *) gc_malloc(256, false, gc);

    *mtu = 0;

    while (true)
    {
        memset(&rcvbuf, -1, sizeof(rcvbuf));
        iov.iov_base = &rcvbuf;
        iov.iov_len = sizeof(rcvbuf);
        msg.msg_name = (uint8_t *) &addr;
        msg.msg_namelen = sizeof(addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_flags = 0;
        msg.msg_control = cbuf;
        msg.msg_controllen = 256; /* size of cbuf */

        res = recvmsg(fd, &msg, MSG_ERRQUEUE);
        if (res < 0)
        {
            goto exit;
        }

        e = NULL;

        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
        {
            if (cmsg->cmsg_level == SOL_IP)
            {
                if (cmsg->cmsg_type == IP_RECVERR)
                {
                    e = (struct sock_extended_err *) CMSG_DATA(cmsg);
                }
                else
                {
                    buf_printf(&out,"CMSG=%d|", cmsg->cmsg_type);
                }
            }
        }
        if (e == NULL)
        {
            buf_printf(&out, "NO-INFO|");
            goto exit;
        }

        switch (e->ee_errno)
        {
            case ETIMEDOUT:
                buf_printf(&out, "ETIMEDOUT|");
                break;

            case EMSGSIZE:
                buf_printf(&out, "EMSGSIZE Path-MTU=%d|", e->ee_info);
                *mtu = e->ee_info;
                break;

            case ECONNREFUSED:
                buf_printf(&out, "ECONNREFUSED|");
                break;

            case EPROTO:
                buf_printf(&out, "EPROTO|");
                break;

            case EHOSTUNREACH:
                buf_printf(&out, "EHOSTUNREACH|");
                break;

            case ENETUNREACH:
                buf_printf(&out, "ENETUNREACH|");
                break;

            case EACCES:
                buf_printf(&out, "EACCES|");
                break;

            default:
                buf_printf(&out, "UNKNOWN|");
                break;
        }
    }

exit:
    buf_rmtail(&out, '|');
    return BSTR(&out);
}

void
set_sock_extended_error_passing(int sd)
{
    int on = 1;
    if (setsockopt(sd, SOL_IP, IP_RECVERR, (void *) &on, sizeof(on)))
    {
        msg(M_WARN | M_ERRNO,
            "Note: enable extended error passing on TCP/UDP socket failed (IP_RECVERR)");
    }
}

#endif /* if EXTENDED_SOCKET_ERROR_CAPABILITY */
