/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
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


/**
 * @file
 * Interface functions to the internal and external multiplexers.
 */


#ifndef FORWARD_H
#define FORWARD_H

#include "openvpn.h"
#include "occ.h"
#include "ping.h"

#define TUN_OUT(c)      (BLEN(&(c)->c2.to_tun) > 0)
#define LINK_OUT(c)     (BLEN(&(c)->c2.to_link) > 0)
#define ANY_OUT(c)      (TUN_OUT(c) || LINK_OUT(c))

#ifdef ENABLE_FRAGMENT
#define TO_LINK_FRAG(c) ((c)->c2.fragment && fragment_outgoing_defined ((c)->c2.fragment))
#else
#define TO_LINK_FRAG(c) (false)
#endif

#define TO_LINK_DEF(c)  (LINK_OUT(c) || TO_LINK_FRAG(c))

#define IOW_TO_TUN          (1<<0)
#define IOW_TO_LINK         (1<<1)
#define IOW_READ_TUN        (1<<2)
#define IOW_READ_LINK       (1<<3)
#define IOW_SHAPER          (1<<4)
#define IOW_CHECK_RESIDUAL  (1<<5)
#define IOW_FRAG            (1<<6)
#define IOW_MBUF            (1<<7)
#define IOW_READ_TUN_FORCE  (1<<8)
#define IOW_WAIT_SIGNAL     (1<<9)

#define IOW_READ            (IOW_READ_TUN|IOW_READ_LINK)


void pre_select (struct context *c);
void process_io (struct context *c);

const char *wait_status_string (struct context *c, struct gc_arena *gc);
void show_wait_status (struct context *c);


/**********************************************************************/
/**
 * Process a data channel packet that will be sent through a VPN tunnel.
 * @ingroup data_control
 *
 * This function controls the processing of a data channel packet which
 * will be sent through a VPN tunnel to a remote OpenVPN peer.  It's
 * general structure is as follows:
 * - Check that the client authentication has succeeded; if not, drop the
 *   packet.
 * - If the \a comp_frag argument is true:
 *   - Call \c lzo_compress() of the \link Data Channel Compression
 *     module\endlink to (possibly) compress the packet.
 *   - Call \c fragment_outgoing() of the \link Data Channel Fragmentation
 *     module\endlink to (possibly) fragment the packet.
 * - Activate the \link Data Channel Crypto module\endlink to perform
 *   security operations on the packet.
 *   - Call \c tls_pre_encrypt() to choose the appropriate security
 *     parameters for this packet.
 *   - Call \c openvpn_encrypt() to encrypt and HMAC signed the packet.
 *   - Call \c tls_post_encrypt() to prepend the one-byte OpenVPN header
 *     and do some TLS accounting.
 * - Place the resulting packet in \c c->c2.to_link so that it can be sent
 *   over the external network interface to its remote destination by the
 *   \link external_multiplexer External Multiplexer\endlink.
 *
 * @param c - The context structure of the VPN tunnel associated with this
 *     packet.
 * @param comp_frag - Whether to do packet compression and fragmentation.
 *     This flag is set to true the first time a packet is processed.  If
 *     the packet then gets fragmented, this function will be called again
 *     once for each remaining fragment with this parameter set to false.
 */
void encrypt_sign (struct context *c, bool comp_frag);


/**********************************************************************/
/**
 * Read a packet from the external network interface.
 * @ingroup external_multiplexer
 *
 * The packet read from the external network interface is stored in \c
 * c->c2.buf and its source address in \c c->c2.from.  If an error
 * occurred, the length of \c c->c2.buf will be 0.
 *
 * OpenVPN running as client or as UDP server only has a single external
 * network socket, so this function can be called with the single (client
 * mode) or top level (UDP server) context as its argument. OpenVPN
 * running as TCP server, on the other hand, has a network socket for each
 * active VPN tunnel.  In that case this function must be called with the
 * context associated with the appropriate VPN tunnel for which data is
 * available to be read.
 *
 * @param c - The context structure which contains the external
 *     network socket from which to read incoming packets.
 */
void read_incoming_link (struct context *c);


/**
 * Process a packet read from the external network interface.
 * @ingroup external_multiplexer
 *
 * This function controls the processing of a data channel packet which
 * has come out of a VPN tunnel.  It's high-level structure is as follows:
 * - Verify that a nonzero length packet has been received from a valid
 *   source address for the given context \a c.
 * - Call \c tls_pre_decrypt(), which splits data channel and control
 *   channel packets:
 *   - If a data channel packet, the appropriate security parameters are
 *     loaded.
 *   - If a control channel packet, this function process is it and
 *     afterwards sets the packet's buffer length to 0, so that the data
 *     channel processing steps below will ignore it.
 * - Call \c openvpn_decrypt() of the \link data_crypto Data Channel
 *   Crypto module\endlink to authenticate and decrypt the packet using
 *   the security parameters loaded by \c tls_pre_decrypt() above.
 * - Call \c fragment_incoming() of the \link fragmentation Data Channel
 *   Fragmentation module\endlink to reassemble the packet if it's
 *   fragmented.
 * - Call \c lzo_decompress() of the \link compression Data Channel
 *   Compression module\endlink to decompress the packet if it's
 *   compressed.
 * - Place the resulting packet in \c c->c2.to_tun so that it can be sent
 *   over the virtual tun/tap network interface to its local destination
 *   by the \link internal_multiplexer Internal Multiplexer\endlink.
 *
 * @param c - The context structure of the VPN tunnel associated with the
 *     packet.
 */
void process_incoming_link (struct context *c);


/**
 * Write a packet to the external network interface.
 * @ingroup external_multiplexer
 *
 * This function writes the packet stored in \c c->c2.to_link to the
 * external network device contained within \c c->c1.link_socket.
 *
 * If an error occurs, it is logged and the packet is dropped.
 *
 * @param c - The context structure of the VPN tunnel associated with the
 *     packet.
 */
void process_outgoing_link (struct context *c);


/**************************************************************************/
/**
 * Read a packet from the virtual tun/tap network interface.
 * @ingroup internal_multiplexer
 *
 * This function reads a packet from the virtual tun/tap network device \c
 * c->c1.tuntap and stores it in \c c->c2.buf.
 *
 * If an error occurs, it is logged and the packet is dropped.
 *
 * @param c - The context structure in which to store the received
 *     packet.
 */
void read_incoming_tun (struct context *c);


/**
 * Process a packet read from the virtual tun/tap network interface.
 * @ingroup internal_multiplexer
 *
 * This function calls \c encrypt_sign() of the \link data_control Data
 * Channel Control module\endlink to process the packet.
 *
 * If an error occurs, it is logged and the packet is dropped.
 *
 * @param c - The context structure of the VPN tunnel associated with the
 *     packet.
 */
void process_incoming_tun (struct context *c);


/**
 * Write a packet to the virtual tun/tap network interface.
 * @ingroup internal_multiplexer
 *
 * This function writes the packet stored in \c c->c2.to_tun to the
 * virtual tun/tap network device \c c->c1.tuntap.
 *
 * If an error occurs, it is logged and the packet is dropped.
 *
 * @param c - The context structure of the VPN tunnel associated with
 *     the packet.
 */
void process_outgoing_tun (struct context *c);


/**************************************************************************/

bool send_control_channel_string (struct context *c, const char *str, int msglevel);

#define PIPV4_PASSTOS         (1<<0)
#define PIP_MSSFIX            (1<<1)         /* v4 and v6 */
#define PIPV4_OUTGOING        (1<<2)
#define PIPV4_EXTRACT_DHCP_ROUTER (1<<3)
#define PIPV4_CLIENT_NAT      (1<<4)

void process_ip_header (struct context *c, unsigned int flags, struct buffer *buf);

#if P2MP
void schedule_exit (struct context *c, const int n_seconds, const int signal);
#endif

#endif /* FORWARD_H */
