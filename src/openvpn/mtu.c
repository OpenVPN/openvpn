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

#include "common.h"
#include "buffer.h"
#include "error.h"
#include "integer.h"
#include "mtu.h"
#include "options.h"
#include "crypto.h"

#include "memdbg.h"

/* allocate a buffer for socket or tun layer */
void
alloc_buf_sock_tun(struct buffer *buf,
                   const struct frame *frame)
{
    /* allocate buffer for overlapped I/O */
    *buf = alloc_buf(BUF_SIZE(frame));
    ASSERT(buf_init(buf, frame->buf.headroom));
    buf->len = frame->buf.payload_size;
    ASSERT(buf_safe(buf, 0));
}

unsigned int
calc_packet_id_size_dc(const struct options *options, const struct key_type *kt)
{
    bool tlsmode = options->tls_server || options->tls_client;

    bool packet_id_long_form = !tlsmode || cipher_kt_mode_ofb_cfb(kt->cipher);

    return packet_id_size(packet_id_long_form);
}

size_t
frame_calculate_protocol_header_size(const struct key_type *kt,
                                     const struct options *options,
                                     bool occ)
{
    /* Sum of all the overhead that reduces the usable packet size */
    size_t header_size = 0;

    bool tlsmode = options->tls_server || options->tls_client;

    /* A socks proxy adds 10 byte of extra header to each packet
     * (we only support Socks with IPv4, this value is different for IPv6) */
    if (options->ce.socks_proxy_server && proto_is_udp(options->ce.proto))
    {
        header_size += 10;
    }

    /* TCP stream based packets have a 16 bit length field */
    if (proto_is_tcp(options->ce.proto))
    {
        header_size += 2;
    }

    /* Add the opcode and peerid */
    if (tlsmode)
    {
        header_size += options->use_peer_id ? 4 : 1;
    }

    unsigned int pkt_id_size = calc_packet_id_size_dc(options, kt);

    /* For figuring out the crypto overhead, we need the size of the payload
     * including all headers that also get encrypted as part of the payload */
    header_size += calculate_crypto_overhead(kt, pkt_id_size, occ);
    return header_size;
}


size_t
frame_calculate_payload_overhead(size_t extra_tun,
                                 const struct options *options,
                                 const struct key_type *kt)
{
    size_t overhead = 0;

    /* This is the overhead of tap device that is not included in the MTU itself
     * i.e. Ethernet header that we still need to transmit as part of the
     * payload, this is set to 0 by caller if not applicable */
    overhead += extra_tun;

#if defined(USE_COMP)
    /* v1 Compression schemes add 1 byte header. V2 only adds a header when it
     * does not increase the packet length. We ignore the unlikely escaping
     * for tap here */
    if (options->comp.alg == COMP_ALG_LZ4 || options->comp.alg == COMP_ALG_STUB
        || options->comp.alg == COMP_ALG_LZO)
    {
        overhead += 1;
    }
#endif
#if defined(ENABLE_FRAGMENT)
    /* Add the size of the fragment header (uint32_t) */
    if (options->ce.fragment)
    {
        overhead += 4;
    }
#endif

    if (cipher_kt_mode_cbc(kt->cipher))
    {
        /* The packet id is part of the plain text payload instead of the
         * cleartext protocol header and needs to be included in the payload
         * overhead instead of the protocol header */
        overhead += calc_packet_id_size_dc(options, kt);
    }

    return overhead;
}

size_t
frame_calculate_payload_size(const struct frame *frame,
                             const struct options *options,
                             const struct key_type *kt)
{
    size_t payload_size = options->ce.tun_mtu;
    payload_size += frame_calculate_payload_overhead(frame->extra_tun, options, kt);
    return payload_size;
}

size_t
calc_options_string_link_mtu(const struct options *o, const struct frame *frame)
{
    struct key_type occ_kt;

    /* neither --secret nor TLS mode */
    if (!o->tls_client && !o->tls_server && !o->shared_secret_file)
    {
        init_key_type(&occ_kt, "none", "none", false, false);
        return frame_calculate_payload_size(frame, o, &occ_kt);
    }

    /* o->ciphername might be BF-CBC even though the underlying SSL library
     * does not support it. For this reason we workaround this corner case
     * by pretending to have no encryption enabled and by manually adding
     * the required packet overhead to the MTU computation.
     */
    const char *ciphername = o->ciphername;

    size_t overhead = 0;

    if (strcmp(o->ciphername, "BF-CBC") == 0)
    {
        /* none has no overhead, so use this to later add only --auth
         * overhead */

        /* overhead of BF-CBC: 64 bit block size, 64 bit IV size */
        overhead += 64/8 + 64/8;
        /* set ciphername to none, so its size does get added in the
         * fake_kt and the cipher is not tried to be resolved */
        ciphername = "none";
    }

    /* We pass tlsmode always true here since as we do not need to check if
     * the ciphers are actually valid for non tls in occ calucation */
    init_key_type(&occ_kt, ciphername, o->authname, true, false);

    size_t payload = frame_calculate_payload_size(frame, o, &occ_kt);
    overhead += frame_calculate_protocol_header_size(&occ_kt, o, true);

    return payload + overhead;
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
    buf_printf(&out, " mss_fix:%" PRIu16, frame->mss_fix);
#ifdef ENABLE_FRAGMENT
    buf_printf(&out, " max_frag:%d", frame->max_fragment_size);
#endif
    buf_printf(&out, " tun_mtu:%d", frame->tun_mtu);
    buf_printf(&out, " tun_max_mtu:%d", frame->tun_max_mtu);
    buf_printf(&out, " headroom:%d", frame->buf.headroom);
    buf_printf(&out, " payload:%d", frame->buf.payload_size);
    buf_printf(&out, " tailroom:%d", frame->buf.tailroom);
    buf_printf(&out, " ET:%d", frame->extra_tun);
    buf_printf(&out, " ]");

    msg(level, "%s", out.data);
    gc_free(&gc);
}

#define MTUDISC_NOT_SUPPORTED_MSG "--mtu-disc is not supported on this OS"

void
set_mtu_discover_type(socket_descriptor_t sd, int mtu_type, sa_family_t proto_af)
{
    if (mtu_type >= 0)
    {
        switch (proto_af)
        {
#if defined(IP_MTU_DISCOVER)
            case AF_INET:
                if (setsockopt(sd, IPPROTO_IP, IP_MTU_DISCOVER,
                               (void *) &mtu_type, sizeof(mtu_type)))
                {
                    msg(M_ERR, "Error setting IP_MTU_DISCOVER type=%d on TCP/UDP socket",
                        mtu_type);
                }
                break;

#endif
#if defined(IPV6_MTU_DISCOVER)
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
    struct sockaddr_storage addr;
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
                    buf_printf(&out, "CMSG=%d|", cmsg->cmsg_type);
                }
            }
            else if (cmsg->cmsg_level == IPPROTO_IPV6)
            {
                if (cmsg->cmsg_type == IPV6_RECVERR)
                {
                    e = (struct sock_extended_err *) CMSG_DATA(cmsg);
                }
                else
                {
                    buf_printf(&out, "CMSG=%d|", cmsg->cmsg_type);
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
set_sock_extended_error_passing(int sd, sa_family_t proto_af)
{
    int on = 1;
    /* see "man 7 ip" (on Linux)
     * this works on IPv4 and IPv6(-dual-stack) sockets (v4-mapped)
     */
    if (setsockopt(sd, SOL_IP, IP_RECVERR, (void *) &on, sizeof(on)) != 0)
    {
        msg(M_WARN | M_ERRNO,
            "Note: enable extended error passing on TCP/UDP socket failed (IP_RECVERR)");
    }
    /* see "man 7 ipv6" (on Linux)
     * this only works on IPv6 sockets
     */
    if (proto_af == AF_INET6
        && setsockopt(sd, IPPROTO_IPV6, IPV6_RECVERR, (void *) &on, sizeof(on)) != 0)
    {
        msg(M_WARN | M_ERRNO,
            "Note: enable extended error passing on TCP/UDP socket failed (IPV6_RECVERR)");
    }
}

#endif /* if EXTENDED_SOCKET_ERROR_CAPABILITY */
