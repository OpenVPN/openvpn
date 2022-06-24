/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2010      Fabian Knittel <fabian.knittel@lettink.de>
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
#include "options.h"
#include "vlan.h"

/*
 * Retrieve the VLAN Identifier (VID) from the IEEE 802.1Q header.
 *
 * @param hdr Pointer to the Ethernet header with IEEE 802.1Q tagging.
 * @return    Returns the VID in host byte order.
 */
static uint16_t
vlanhdr_get_vid(const struct openvpn_8021qhdr *hdr)
{
    return ntohs(hdr->pcp_cfi_vid & OPENVPN_8021Q_MASK_VID);
}

/*
 * Set the VLAN Identifier (VID) in an IEEE 802.1Q header.
 *
 * @param hdr Pointer to the Ethernet header with IEEE 802.1Q tagging.
 * @param vid The VID to set (in host byte order).
 */
static void
vlanhdr_set_vid(struct openvpn_8021qhdr *hdr, const uint16_t vid)
{
    hdr->pcp_cfi_vid = (hdr->pcp_cfi_vid & ~OPENVPN_8021Q_MASK_VID)
                       | (htons(vid) & OPENVPN_8021Q_MASK_VID);
}

/*
 * vlan_decapsulate - remove 802.1q header and return VID
 *
 * For vlan_accept == VLAN_ONLY_UNTAGGED_OR_PRIORITY:
 *   Only untagged frames and frames that are priority-tagged (VID == 0) are
 *   accepted.  (This means that VLAN-tagged frames are dropped.)  For frames
 *   that aren't dropped, the global vlan_pvid is returned as VID.
 *
 * For vlan_accept == VLAN_ONLY_TAGGED:
 *   If a frame is VLAN-tagged the tagging is removed and the embedded VID is
 *   returned.  Any included priority information is lost.
 *   If a frame isn't VLAN-tagged, the frame is dropped.
 *
 * For vlan_accept == VLAN_ALL:
 *   Accepts both VLAN-tagged and untagged (or priority-tagged) frames and
 *   and handles them as described above.
 *
 * @param c   The global context.
 * @param buf The ethernet frame.
 * @return    Returns -1 if the frame is dropped or the VID if it is accepted.
 */
int16_t
vlan_decapsulate(const struct context *c, struct buffer *buf)
{
    const struct openvpn_8021qhdr *vlanhdr;
    struct openvpn_ethhdr *ethhdr;
    uint16_t vid;

    /* assume untagged frame */
    if (BLEN(buf) < sizeof(*ethhdr))
    {
        goto drop;
    }

    ethhdr = (struct openvpn_ethhdr *)BPTR(buf);
    if (ethhdr->proto != htons(OPENVPN_ETH_P_8021Q))
    {
        /* reject untagged frame */
        if (c->options.vlan_accept == VLAN_ONLY_TAGGED)
        {
            msg(D_VLAN_DEBUG,
                "dropping frame without vlan-tag (proto/len 0x%04x)",
                ntohs(ethhdr->proto));
            goto drop;
        }

        /* untagged frame is accepted and associated with the global VID */
        msg(D_VLAN_DEBUG,
            "assuming pvid for frame without vlan-tag, pvid: %u (proto/len 0x%04x)",
            c->options.vlan_pvid, ntohs(ethhdr->proto));

        return c->options.vlan_pvid;
    }

    /* tagged frame */
    if (BLEN(buf) < sizeof(*vlanhdr))
    {
        goto drop;
    }

    vlanhdr = (const struct openvpn_8021qhdr *)BPTR(buf);
    vid = vlanhdr_get_vid(vlanhdr);

    switch (c->options.vlan_accept)
    {
        case VLAN_ONLY_UNTAGGED_OR_PRIORITY:
            /* VLAN-tagged frame: drop packet */
            if (vid != 0)
            {
                msg(D_VLAN_DEBUG, "dropping frame with vlan-tag, vid: %u (proto/len 0x%04x)",
                    vid, ntohs(vlanhdr->proto));
                goto drop;
            }

        /* vid == 0 means prio-tagged packet: don't drop and fall-through */
        case VLAN_ONLY_TAGGED:
        case VLAN_ALL:
            /* tagged frame can be accepted: extract vid and strip encapsulation */

            /* in case of prio-tagged frame (vid == 0), assume the sender
             * knows what he is doing and forward the packet as it is, so to
             * keep the priority information intact.
             */
            if (vid == 0)
            {
                /* return the global VID for priority-tagged frames */
                return c->options.vlan_pvid;
            }

            /* here we have a proper VLAN tagged frame: perform decapsulation
             * and return embedded VID
             */
            msg(D_VLAN_DEBUG,
                "removing vlan-tag from frame: vid: %u, wrapped proto/len: 0x%04x",
                vid, ntohs(vlanhdr->proto));

            /* save inner protocol to be restored later after decapsulation */
            uint16_t proto = vlanhdr->proto;
            /* move the buffer head forward to adjust the headroom to a
             * non-tagged frame
             */
            buf_advance(buf, SIZE_ETH_TO_8021Q_HDR);
            /* move the content of the 802.1q header to the new head, so that
             * src/dst addresses are copied over
             */
            ethhdr = memmove(BPTR(buf), vlanhdr, sizeof(*ethhdr));
            /* restore the inner protocol value */
            ethhdr->proto = proto;

            return vid;
    }

drop:
    buf->len = 0;
    return -1;
}

/*
 * vlan_encapsulate - add 802.1q header and set the context related VID
 *
 * Assumes vlan_accept == VLAN_ONLY_TAGGED
 *
 * @param c   The current context.
 * @param buf The ethernet frame to encapsulate.
 */
void
vlan_encapsulate(const struct context *c, struct buffer *buf)
{
    const struct openvpn_ethhdr *ethhdr;
    struct openvpn_8021qhdr *vlanhdr;

    if (BLEN(buf) < sizeof(*ethhdr))
    {
        goto drop;
    }

    ethhdr = (const struct openvpn_ethhdr *)BPTR(buf);
    if (ethhdr->proto == htons(OPENVPN_ETH_P_8021Q))
    {
        /* Priority-tagged frame. (VLAN-tagged frames have been dropped before
         * getting to this point)
         */

        /* Frame too small for header type? */
        if (BLEN(buf) < sizeof(*vlanhdr))
        {
            goto drop;
        }

        vlanhdr = (struct openvpn_8021qhdr *)BPTR(buf);

        /* sanity check: ensure this packet is really just prio-tagged */
        uint16_t vid = vlanhdr_get_vid(vlanhdr);
        if (vid != 0)
        {
            goto drop;
        }
    }
    else
    {
        /* Untagged frame. */

        /* Not enough head room for VLAN tag? */
        if (buf_reverse_capacity(buf) < SIZE_ETH_TO_8021Q_HDR)
        {
            goto drop;
        }

        vlanhdr = (struct openvpn_8021qhdr *)buf_prepend(buf,
                                                         SIZE_ETH_TO_8021Q_HDR);

        /* Initialise VLAN/802.1q header.
         * Move the Eth header so to keep dst/src addresses the same and then
         * assign the other fields.
         *
         * Also, save the inner protocol first, so that it can be restored later
         * after the memmove()
         */
        uint16_t proto = ethhdr->proto;
        memmove(vlanhdr, ethhdr, sizeof(*ethhdr));
        vlanhdr->tpid = htons(OPENVPN_ETH_P_8021Q);
        vlanhdr->pcp_cfi_vid = 0;
        vlanhdr->proto = proto;
    }

    /* set the VID corresponding to the current context (client) */
    vlanhdr_set_vid(vlanhdr, c->options.vlan_pvid);

    msg(D_VLAN_DEBUG, "tagging frame: vid %u (wrapping proto/len: %04x)",
        c->options.vlan_pvid, vlanhdr->proto);
    return;

drop:
    /* Drop the frame. */
    buf->len = 0;
}

/*
 * vlan_is_tagged - check if a packet is VLAN-tagged
 *
 * Checks whether ethernet frame is VLAN-tagged.
 *
 * @param buf The ethernet frame.
 * @return    Returns true if the frame is VLAN-tagged, false otherwise.
 */
bool
vlan_is_tagged(const struct buffer *buf)
{
    const struct openvpn_8021qhdr *vlanhdr;
    uint16_t vid;

    if (BLEN(buf) < sizeof(struct openvpn_8021qhdr))
    {
        /* frame too small to be VLAN-tagged */
        return false;
    }

    vlanhdr = (const struct openvpn_8021qhdr *)BPTR(buf);

    if (ntohs(vlanhdr->tpid) != OPENVPN_ETH_P_8021Q)
    {
        /* non tagged frame */
        return false;
    }

    vid = vlanhdr_get_vid(vlanhdr);
    if (vid == 0)
    {
        /* no vid: piority tagged only */
        return false;
    }

    return true;
}

void
vlan_process_outgoing_tun(struct multi_context *m, struct multi_instance *mi)
{
    if (!m->top.options.vlan_tagging)
    {
        return;
    }

    if (m->top.options.vlan_accept == VLAN_ONLY_UNTAGGED_OR_PRIORITY)
    {
        /* Packets forwarded to the TAP devices aren't VLAN-tagged. Only packets
         * matching the PVID configured globally are allowed to be received
         */
        if (m->top.options.vlan_pvid != mi->context.options.vlan_pvid)
        {
            /* Packet is coming from the wrong VID, drop it.  */
            mi->context.c2.to_tun.len = 0;
        }
    }
    else if (m->top.options.vlan_accept == VLAN_ALL)
    {
        /* Packets either need to be VLAN-tagged or not, depending on the
         * packet's originating VID and the port's native VID (PVID).  */

        if (m->top.options.vlan_pvid != mi->context.options.vlan_pvid)
        {
            /* Packets need to be VLAN-tagged, because the packet's VID does not
             * match the port's PVID.  */
            vlan_encapsulate(&mi->context, &mi->context.c2.to_tun);
        }
    }
    else if (m->top.options.vlan_accept == VLAN_ONLY_TAGGED)
    {
        /* All packets on the port (the tap device) need to be VLAN-tagged.  */
        vlan_encapsulate(&mi->context, &mi->context.c2.to_tun);
    }
}
