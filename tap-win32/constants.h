/*
 *  TAP-Win32 -- A kernel driver to provide virtual tap device functionality
 *               on Windows.  Originally derived from the CIPE-Win32
 *               project by Damion K. Wilson, with extensive modifications by
 *               James Yonan.
 *
 *  All source code which derives from the CIPE-Win32 project is
 *  Copyright (C) Damion K. Wilson, 2003, and is released under the
 *  GPL version 2 (see below).
 *
 *  All other source code is Copyright (C) 2002-2005 OpenVPN Solutions LLC,
 *  and is released under the GPL version 2 (see below).
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

//====================================================================
//                        Product and Version public settings
//====================================================================

#define PRODUCT_STRING "TAP-Win32 Adapter V8"

#define TAP_NDIS_MAJOR_VERSION 5
#define TAP_NDIS_MINOR_VERSION 0

//===========================================================
// Driver constants
//===========================================================

#define ETHERNET_HEADER_SIZE     (sizeof (ETH_HEADER))
#define ETHERNET_MTU             1500
#define ETHERNET_PACKET_SIZE     (ETHERNET_MTU + ETHERNET_HEADER_SIZE)
#define DEFAULT_PACKET_LOOKAHEAD (ETHERNET_PACKET_SIZE)

#define NIC_MAX_MCAST_LIST 32  // Max length of multicast address list

#define MINIMUM_MTU 576        // USE TCP Minimum MTU
#define MAXIMUM_MTU 65536      // IP maximum MTU

#define PACKET_QUEUE_SIZE   64 // tap -> userspace queue size
#define IRP_QUEUE_SIZE      16 // max number of simultaneous i/o operations from userspace

#define TAP_LITTLE_ENDIAN      // affects ntohs, htonl, etc. functions
