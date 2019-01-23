/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
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
#include "error.h"
#include "mss.h"
#include "memdbg.h"

/*
 * Lower MSS on TCP SYN packets to fix MTU
 * problems which arise from protocol
 * encapsulation.
 */

/*
 * IPv4 packet: find TCP header, check flags for "SYN"
 *              if yes, hand to mss_fixup_dowork()
 */
void
mss_fixup_ipv4(struct buffer *buf, int maxmss)
{
    const struct openvpn_iphdr *pip;
    int hlen;

    if (BLEN(buf) < (int) sizeof(struct openvpn_iphdr))
    {
        return;
    }

    verify_align_4(buf);
    pip = (struct openvpn_iphdr *) BPTR(buf);

    hlen = OPENVPN_IPH_GET_LEN(pip->version_len);

    if (pip->protocol == OPENVPN_IPPROTO_TCP
        && ntohs(pip->tot_len) == BLEN(buf)
        && (ntohs(pip->frag_off) & OPENVPN_IP_OFFMASK) == 0
        && hlen <= BLEN(buf)
        && BLEN(buf) - hlen
        >= (int) sizeof(struct openvpn_tcphdr))
    {
        struct buffer newbuf = *buf;
        if (buf_advance(&newbuf, hlen))
        {
            struct openvpn_tcphdr *tc = (struct openvpn_tcphdr *) BPTR(&newbuf);
            if (tc->flags & OPENVPN_TCPH_SYN_MASK)
            {
                mss_fixup_dowork(&newbuf, (uint16_t) maxmss);
            }
        }
    }
}

/*
 * IPv6 packet: find TCP header, check flags for "SYN"
 *              if yes, hand to mss_fixup_dowork()
 *              (IPv6 header structure is sufficiently different from IPv4...)
 */
void
mss_fixup_ipv6(struct buffer *buf, int maxmss)
{
    const struct openvpn_ipv6hdr *pip6;
    struct buffer newbuf;

    if (BLEN(buf) < (int) sizeof(struct openvpn_ipv6hdr))
    {
        return;
    }

    verify_align_4(buf);
    pip6 = (struct openvpn_ipv6hdr *) BPTR(buf);

    /* do we have the full IPv6 packet?
     * "payload_len" does not include IPv6 header (+40 bytes)
     */
    if (BLEN(buf) != (int) ntohs(pip6->payload_len)+40)
    {
        return;
    }

    /* follow header chain until we reach final header, then check for TCP
     *
     * An IPv6 packet could, theoretically, have a chain of multiple headers
     * before the final header (TCP, UDP, ...), so we'd need to walk that
     * chain (see RFC 2460 and RFC 6564 for details).
     *
     * In practice, "most typically used" extension headers (AH, routing,
     * fragment, mobility) are very unlikely to be seen inside an OpenVPN
     * tun, so for now, we only handle the case of "single next header = TCP"
     */
    if (pip6->nexthdr != OPENVPN_IPPROTO_TCP)
    {
        return;
    }

    /* skip IPv6 header (40 bytes),
     * verify remainder is large enough to contain a full TCP header
     */
    newbuf = *buf;
    if (buf_advance( &newbuf, 40 )
        && BLEN(&newbuf) >= (int) sizeof(struct openvpn_tcphdr))
    {
        struct openvpn_tcphdr *tc = (struct openvpn_tcphdr *) BPTR(&newbuf);
        if (tc->flags & OPENVPN_TCPH_SYN_MASK)
        {
            mss_fixup_dowork(&newbuf, (uint16_t) maxmss-20);
        }
    }
}

/*
 * change TCP MSS option in SYN/SYN-ACK packets, if present
 * this is generic for IPv4 and IPv6, as the TCP header is the same
 */

void
mss_fixup_dowork(struct buffer *buf, uint16_t maxmss)
{
    int hlen, olen, optlen;
    uint8_t *opt;
    uint16_t mssval;
    int accumulate;
    struct openvpn_tcphdr *tc;

    if (BLEN(buf) < (int) sizeof(struct openvpn_tcphdr))
    {
        return;
    }

    verify_align_4(buf);
    tc = (struct openvpn_tcphdr *) BPTR(buf);
    hlen = OPENVPN_TCPH_GET_DOFF(tc->doff_res);

    /* Invalid header length or header without options. */
    if (hlen <= (int) sizeof(struct openvpn_tcphdr)
        || hlen > BLEN(buf))
    {
        return;
    }

    for (olen = hlen - sizeof(struct openvpn_tcphdr),
         opt = (uint8_t *)(tc + 1);
         olen > 1;
         olen -= optlen, opt += optlen)
    {
        if (*opt == OPENVPN_TCPOPT_EOL)
        {
            break;
        }
        else if (*opt == OPENVPN_TCPOPT_NOP)
        {
            optlen = 1;
        }
        else
        {
            optlen = *(opt + 1);
            if (optlen <= 0 || optlen > olen)
            {
                break;
            }
            if (*opt == OPENVPN_TCPOPT_MAXSEG)
            {
                if (optlen != OPENVPN_TCPOLEN_MAXSEG)
                {
                    continue;
                }
                mssval = (opt[2]<<8)+opt[3];
                if (mssval > maxmss)
                {
                    dmsg(D_MSS, "MSS: %d -> %d", (int) mssval, (int) maxmss);
                    accumulate = htons(mssval);
                    opt[2] = (maxmss>>8)&0xff;
                    opt[3] = maxmss&0xff;
                    accumulate -= htons(maxmss);
                    ADJUST_CHECKSUM(accumulate, tc->check);
                }
            }
        }
    }
}
