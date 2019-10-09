/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2019 OpenVPN Technologies, Inc. <sales@openvpn.net>
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

#if P2MP_SERVER

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
}

#endif /* P2MP_SERVER */
