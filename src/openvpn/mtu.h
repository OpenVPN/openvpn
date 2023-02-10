/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
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

#ifndef MTU_H
#define MTU_H

#include "buffer.h"

/*
 *
 * Packet manipulation routes such as encrypt, decrypt, compress, decompress
 * are passed a frame buffer that looks like this:
 *
 *    [extra_frame bytes] [mtu bytes] [extra_frame_bytes] [compression overflow bytes]
 *                         ^
 *                   Pointer passed to function points here so that routine
 *                   can make use of extra_frame bytes before pointer
 *                   to prepend headers, etc.
 *
 *    extra_frame bytes is large enough for all encryption related overhead.
 *
 *    mtu bytes will be the MTU size set in the ifconfig statement that configures
 *      the TUN or TAP device such as:
 *
 *      ifconfig $1 10.1.0.2 pointopoint 10.1.0.1 mtu 1450
 *
 *    Compression overflow bytes is the worst-case size expansion that would be
 *    expected if we tried to compress mtu + extra_frame bytes of incompressible data.
 */

/*
 * Standard ethernet MTU
 */
#define ETHERNET_MTU       1500

/*
 * It is a fatal error if mtu is less than
 * this value for tun device.
 */
#define TUN_MTU_MIN        100

/*
 * Default MTU of network over which tunnel data will pass by TCP/UDP.
 */
#define LINK_MTU_DEFAULT   1500

/*
 * Default MTU of tunnel device.
 */
#define TUN_MTU_DEFAULT    1500

/*
 * MTU Defaults for TAP devices
 */
#define TAP_MTU_EXTRA_DEFAULT  32

/*
 * Default MSSFIX value, used for reducing TCP MTU size
 */
#define MSSFIX_DEFAULT     1492

/*
 * Default maximum size of control channel packets
 */
#define TLS_MTU_DEFAULT    1250

/*
 * Alignment of payload data such as IP packet or
 * ethernet frame.
 */
#define PAYLOAD_ALIGN 4


/**************************************************************************/
/**
 * Packet geometry parameters.
 */
struct frame {
    struct {
        /* This struct holds all the information about the buffers that are
         * allocated to match this frame */
        int payload_size;       /**< the maximum size that a payload that our
                                 *   buffers can hold from either tun device
                                 *   or network link.
                                 */


        int headroom;           /**< the headroom in the buffer, this is choosen
                                 *   to allow all potential header to be added
                                 *   before the packet */

        int tailroom;            /**< the tailroom in the buffer. Chosen large
                                  *  enough to also accompany any extrea header
                                  *  or work space required by
                                  *  decryption/encryption or compression. */
    } buf;

    unsigned int mss_fix;       /**< The actual MSS value that should be
                                 *   written to the payload packets. This
                                 *   is the value for IPv4 TCP packets. For
                                 *   IPv6 packets another 20 bytes must
                                 *   be subtracted */

    int max_fragment_size;      /**< The maximum size of a fragment.
                                 * Fragmentation is done on the unencrypted
                                 * payload after (potential) compression. So
                                 * this value specifies the maximum payload
                                 * size that can be send in a single fragment
                                 */

    int tun_mtu;                /**< the (user) configured tun-mtu. This is used
                                 *   in configuring the tun interface or
                                 *   in calculations that use the desired size
                                 *   of the payload in the buffer.
                                 *
                                 *   This variable is also used in control
                                 *   frame context to set the desired maximum
                                 *   control frame payload (although most of
                                 *   code ignores it)
                                 */
    int tun_max_mtu;            /**< the maximum tun-mtu size the buffers are
                                 *   are sized for. This is the upper bound that
                                 *   a server can push as MTU */

    int extra_tun;              /**< Maximum number of bytes in excess of
                                 *   the tun/tap MTU that might be read
                                 *   from or written to the virtual
                                 *   tun/tap network interface.
                                 *
                                 *   Only set with the option --tun-mtu-extra
                                 *   which defaults to 0 for tun and 32
                                 *   (\c TAP_MTU_EXTRA_DEFAULT) for tap.
                                 *   */
};

/* Forward declarations, to prevent includes */
struct options;

/*
 * Control buffer headroom allocations to allow for efficient prepending.
 */

/*
 * Max size of a buffer used to build a packet for output to
 * the TCP/UDP port or to read a packet from a tap/tun device.
 *
 * Most of our code only prepends headers but compression needs the extra bytes
 * *after* the data as compressed data might end up larger than the original
 * data. Also crypto needs an extra block for encryption. Therefore tailroom is
 * larger than the headroom.
 */
#define BUF_SIZE(f) ((f)->buf.headroom + (f)->buf.payload_size + (f)->buf.tailroom)

/*
 * Function prototypes.
 */

void frame_print(const struct frame *frame,
                 int level,
                 const char *prefix);

void set_mtu_discover_type(socket_descriptor_t sd, int mtu_type, sa_family_t proto_af);

int translate_mtu_discover_type_name(const char *name);

/* forward declaration of key_type */
struct key_type;

/**
 * Calculates the size of the payload according to tun-mtu and tap overhead. In
 * this context payload is identical to the size of the plaintext.
 * This also includes compression, fragmentation overhead, and packet id in CBC
 * mode if these options are used.
 *
 *
 * *  [IP][UDP][OPENVPN PROTOCOL HEADER][ **PAYLOAD incl compression header** ]
 */
size_t
frame_calculate_payload_size(const struct frame *frame,
                             const struct options *options,
                             const struct key_type *kt);

/**
 * Calculates the size of the payload overhead according to tun-mtu and
 * tap overhead. This all the overhead that is considered part of the payload
 * itself. The compression and fragmentation header and extra header from tap
 * are considered part of this overhead that increases the payload larger than
 * tun-mtu.
 *
 * In CBC mode, the IV is part of the payload instead of part of the OpenVPN
 * protocol header and is included in the returned value.
 *
 * In this context payload is identical to the size of the plaintext and this
 * method can be also understand as number of bytes that are added to the
 * plaintext before encryption.
 *
 * *  [IP][UDP][OPENVPN PROTOCOL HEADER][ **PAYLOAD incl compression header** ]
 */
size_t
frame_calculate_payload_overhead(size_t extra_tun,
                                 const struct options *options,
                                 const struct key_type *kt);


/**
 * Calculates the size of the OpenVPN protocol header. This includes
 * the crypto IV/tag/HMAC but does not include the IP encapsulation
 *
 *  This does NOT include the padding and rounding of CBC size
 *  as the users (mssfix/fragment) of this function need to adjust for
 *  this and add it themselves.
 *
 *  [IP][UDP][ **OPENVPN PROTOCOL HEADER**][PAYLOAD incl compression header]
 *
 * @param kt            the key_type to use to calculate the crypto overhead
 * @param options       the options struct to be used to calculate
 * @param occ           Use the calculation for the OCC link-mtu
 * @return              size of the overhead in bytes
 */
size_t
frame_calculate_protocol_header_size(const struct key_type *kt,
                                     const struct options *options,
                                     bool occ);

/**
 * Calculate the link-mtu to advertise to our peer.  The actual value is not
 * relevant, because we will possibly perform data channel cipher negotiation
 * after this, but older clients will log warnings if we do not supply them the
 * value they expect.  This assumes that the traditional cipher/auth directives
 * in the config match the config of the peer.
 */
size_t
calc_options_string_link_mtu(const struct options *options,
                             const struct frame *frame);

/**
 * Return the size of the packet ID size that is currently in use by cipher and
 * options for the data channel.
 */
unsigned int
calc_packet_id_size_dc(const struct options *options,
                       const struct key_type *kt);

/*
 * allocate a buffer for socket or tun layer
 */
void alloc_buf_sock_tun(struct buffer *buf,
                        const struct frame *frame);

/*
 * EXTENDED_SOCKET_ERROR_CAPABILITY functions -- print extra error info
 * on socket errors, such as PMTU size.  As of 2003.05.11, only works
 * on Linux 2.4+.
 */

#if EXTENDED_SOCKET_ERROR_CAPABILITY

void set_sock_extended_error_passing(int sd, sa_family_t proto_af);

const char *format_extended_socket_error(int fd, int *mtu, struct gc_arena *gc);

#endif

#endif /* ifndef MTU_H */
