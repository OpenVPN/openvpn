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


/**
 * @file
 * Interface functions to the internal and external multiplexers.
 */


#ifndef FORWARD_H
#define FORWARD_H

/* the following macros must be defined before including any other header
 * file
 */

#define BULK_MODE(c) (c->c2.frame.bulk_size > 0)
#define BULK_DATA(b) (b && (b->bulk_leng > 0) && (b->bulk_indx < b->bulk_leng))
#define INST_LENG(a) (a && (a->inst_leng > 0) && (a->inst_indx < a->inst_leng) && (a->pending == NULL))

#define TUN_OUT(c)  (BLEN(&(c)->c2.to_tun) > 0)
#define LINK_OUT(c) (BLEN(&(c)->c2.to_link) > 0)
#define ANY_OUT(c)  (TUN_OUT(c) || LINK_OUT(c))

#ifdef ENABLE_FRAGMENT
#define TO_LINK_FRAG(c) ((c)->c2.fragment && fragment_outgoing_defined((c)->c2.fragment))
#else
#define TO_LINK_FRAG(c) (false)
#endif

#define TO_LINK_DEF(c) (LINK_OUT(c) || TO_LINK_FRAG(c))

#include "openvpn.h"
#include "occ.h"
#include "ping.h"
#include "multi_io.h"

#define IOW_TO_TUN         (1 << 0)
#define IOW_TO_LINK        (1 << 1)
#define IOW_READ_TUN       (1 << 2)
#define IOW_READ_LINK      (1 << 3)
#define IOW_SHAPER         (1 << 4)
#define IOW_CHECK_RESIDUAL (1 << 5)
#define IOW_FRAG           (1 << 6)
#define IOW_MBUF           (1 << 7)
#define IOW_READ_TUN_FORCE (1 << 8)
#define IOW_WAIT_SIGNAL    (1 << 9)

#define IOW_READ (IOW_READ_TUN | IOW_READ_LINK)

extern counter_type link_read_bytes_global;

extern counter_type link_write_bytes_global;

void get_io_flags_dowork_udp(struct context *c, struct multi_io *multi_io,
                             const unsigned int flags);

void get_io_flags_udp(struct context *c, struct multi_io *multi_io, const unsigned int flags);

void io_wait_dowork(struct context *c, const unsigned int flags);

void pre_select(struct context *c);

void process_io(struct context *c, struct link_socket *sock);


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
 *   - Call \c lzo_compress() of the \link compression Data Channel Compression
 *     module\endlink to (possibly) compress the packet.
 *   - Call \c fragment_outgoing() of the \link fragmentation Data Channel Fragmentation
 *     module\endlink to (possibly) fragment the packet.
 * - Activate the \link data_crypto Data Channel Crypto module\endlink to perform
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
void encrypt_sign(struct context *c, bool comp_frag);

int get_server_poll_remaining_time(struct event_timeout *server_poll_timeout);

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
 * @param c    The context structure which contains the external
 *             network socket from which to read incoming packets.
 * @param sock   The socket where the packet can be read from.
 */
void read_incoming_link(struct context *c, struct link_socket *sock);

/**
 * Starts processing a packet read from the external network interface.
 * @ingroup external_multiplexer
 *
 * This function starts the processing of a data channel packet which
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
 *
 * @param c - The context structure of the VPN tunnel associated with the
 *     packet.
 * @param lsi - link_socket_info obtained from context before processing.
 * @param floated - Flag indicates that peer has floated.
 *
 * @return true if packet is authenticated, false otherwise.
 */
bool process_incoming_link_part1(struct context *c, struct link_socket_info *lsi, bool floated);

/**
 * Continues processing a packet read from the external network interface.
 * @ingroup external_multiplexer
 *
 * This function continues the processing of a data channel packet which
 * has come out of a VPN tunnel. It must be called after
 * \c process_incoming_link_part1() function.
 *
 * It's high-level structure is as follows:
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
 * @param lsi - link_socket_info obtained from context before processing.
 * @param orig_buf - Pointer to a buffer data.
 *
 */
void process_incoming_link_part2(struct context *c, struct link_socket_info *lsi,
                                 const uint8_t *orig_buf);

void process_incoming_link_part3(struct context *c);

/**
 * Transfers \c float_sa data extracted from an incoming DCO
 * PEER_FLOAT_NTF to \c out_osaddr for later processing.
 *
 * @param socket_family - The address family of the socket
 * @param out_osaddr - openvpn_sockaddr struct that will be filled the new
 *      address data
 * @param float_sa - The sockaddr struct containing the data received from the
 *      DCO notification
 */
void extract_dco_float_peer_addr(sa_family_t socket_family, struct openvpn_sockaddr *out_osaddr,
                                 const struct sockaddr *float_sa);

/**
 * Write a packet to the external network interface.
 * @ingroup external_multiplexer
 *
 * This function writes the packet stored in \c c->c2.to_link to the
 * external network device contained within \c c->c1.link_socket.
 *
 * If an error occurs, it is logged and the packet is dropped.
 *
 * @param c   The context structure of the VPN tunnel associated with the
 *            packet.
 * @param sock  The socket to be used to send the packet.
 */
void process_outgoing_link(struct context *c, struct link_socket *sock);


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
void read_incoming_tun(struct context *c);


/**
 * Process a packet read from the virtual tun/tap network interface.
 * @ingroup internal_multiplexer
 *
 * This function calls \c encrypt_sign() of the \link data_control Data
 * Channel Control module\endlink to process the packet.
 *
 * If an error occurs, it is logged and the packet is dropped.
 *
 * @param c       The context structure of the VPN tunnel associated with
 *                the packet.
 * @param out_sock  Socket that will be used to send out the packet.
 *
 */
void process_incoming_tun(struct context *c, struct link_socket *out_sock);


/**
 * Write a packet to the virtual tun/tap network interface.
 * @ingroup internal_multiplexer
 *
 * This function writes the packet stored in \c c->c2.to_tun to the
 * virtual tun/tap network device \c c->c1.tuntap.
 *
 * If an error occurs, it is logged and the packet is dropped.
 *
 * @param c      The context structure of the VPN tunnel associated
 *               with the packet.
 * @param in_sock  Socket where the packet was received.
 */
void process_outgoing_tun(struct context *c, struct link_socket *in_sock);


/**************************************************************************/

/*
 * Send a string to remote over the TLS control channel.
 * Used for push/pull messages, passing username/password,
 * etc.
 * @param c          - The context structure of the VPN tunnel associated with
 *                     the packet.
 * @param str        - The message to be sent
 * @param msglevel   - Message level to use for logging
 */
bool send_control_channel_string(struct context *c, const char *str, msglvl_t msglevel);

/*
 * Send a string to remote over the TLS control channel.
 * Used for push/pull messages, auth pending and other clear text
 * control messages.
 *
 * This variant does not schedule the actual sending of the message
 * The caller needs to ensure that it is scheduled or call
 * send_control_channel_string
 *
 * @param session    - The session structure of the VPN tunnel associated
 *                     with the packet. The method will always use the
 *                     primary key (KS_PRIMARY) for sending the message
 * @param str        - The message to be sent
 * @param msglevel   - Message level to use for logging
 */

bool send_control_channel_string_dowork(struct tls_session *session, const char *str,
                                        msglvl_t msglevel);


/**
 * Reschedule tls_multi_process.
 * NOTE: in multi-client mode, usually calling the function is
 * insufficient to reschedule the client instance object unless
 * multi_schedule_context_wakeup(m, mi) is also called.
 */
void reschedule_multi_process(struct context *c);

#define PIPV4_PASSTOS             (1u << 0)
#define PIP_MSSFIX                (1u << 1) /* v4 and v6 */
#define PIP_OUTGOING              (1u << 2)
#define PIPV4_EXTRACT_DHCP_ROUTER (1u << 3)
#define PIPV4_CLIENT_NAT          (1u << 4)
#define PIPV6_ICMP_NOHOST_CLIENT  (1u << 5)
#define PIPV6_ICMP_NOHOST_SERVER  (1u << 6)


void process_ip_header(struct context *c, unsigned int flags, struct buffer *buf,
                       struct link_socket *sock);

bool schedule_exit(struct context *c);

static inline struct link_socket_info *
get_link_socket_info(struct context *c)
{
    if (c->c2.link_socket_infos)
    {
        return c->c2.link_socket_infos[0];
    }
    else
    {
        return &c->c2.link_sockets[0]->info;
    }
}

static inline void
register_activity(struct context *c, const int size)
{
    if (c->options.inactivity_timeout)
    {
        c->c2.inactivity_bytes += size;
        if (c->c2.inactivity_bytes >= c->options.inactivity_minimum_bytes)
        {
            c->c2.inactivity_bytes = 0;
            event_timeout_reset(&c->c2.inactivity_interval);
        }
    }
}

/*
 * Return the io_wait() flags appropriate for
 * a point-to-point tunnel.
 */
static inline unsigned int
p2p_iow_flags(const struct context *c)
{
    unsigned int flags = (IOW_SHAPER | IOW_CHECK_RESIDUAL | IOW_FRAG | IOW_READ | IOW_WAIT_SIGNAL);
    if (c->c2.to_link.len > 0)
    {
        flags |= IOW_TO_LINK;
    }
    if (c->c2.to_tun.len > 0)
    {
        flags |= IOW_TO_TUN;
    }
    return flags;
}

/*
 * This is the core I/O wait function, used for all I/O waits except
 * for the top-level server sockets.
 */
static inline void
io_wait(struct context *c, const unsigned int flags)
{
    if (proto_is_dgram(c->c2.link_sockets[0]->info.proto) && c->c2.fast_io
        && (flags & (IOW_TO_TUN | IOW_TO_LINK | IOW_MBUF)))
    {
        /* fast path -- only for TUN/TAP/UDP writes */
        unsigned int ret = 0;
        if (flags & IOW_TO_TUN)
        {
            ret |= TUN_WRITE;
        }
        if (flags & (IOW_TO_LINK | IOW_MBUF))
        {
            ret |= SOCKET_WRITE;
        }
        c->c2.event_set_status = ret;
    }
    else
    {
        /* slow path */
        io_wait_dowork(c, flags);
    }
}

static inline bool
connection_established(struct context *c)
{
    if (c->c2.tls_multi)
    {
        return c->c2.tls_multi->multi_state >= CAS_WAITING_OPTIONS_IMPORT;
    }
    else
    {
        return get_link_socket_info(c)->connection_established;
    }
}

#endif /* FORWARD_H */
