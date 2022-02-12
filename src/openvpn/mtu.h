/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
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

    int link_mtu;               /**< Maximum packet size to be sent over
                                 *   the external network interface. */

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

    int extra_frame;            /**< Maximum number of bytes that all
                                 *   processing steps together could add.
                                 *   @code
                                 *   frame.link_mtu = "socket MTU" - extra_frame;
                                 *   @endcode
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

    int extra_buffer;           /**< Maximum number of bytes that
                                 *   processing steps could expand the
                                 *   internal work buffer.
                                 *
                                 *   This is used by the \link compression
                                 *   Data Channel Compression
                                 *   module\endlink to give enough working
                                 *   space for worst-case expansion of
                                 *   incompressible content. */

    int extra_tun;              /**< Maximum number of bytes in excess of
                                 *   the tun/tap MTU that might be read
                                 *   from or written to the virtual
                                 *   tun/tap network interface.
                                 *
                                 *   Only set with the option --tun-mtu-extra
                                 *   which defaults to 0 for tun and 32
                                 *   (\c TAP_MTU_EXTRA_DEFAULT) for tap.
                                 *   */

    int extra_link;             /**< Maximum number of bytes in excess of
                                 *   external network interface's MTU that
                                 *   might be read from or written to it.
                                 *
                                 *   Used by peer-id (3) and
                                 *   socks UDP (10) */
};

/* Forward declarations, to prevent includes */
struct options;

/* Routines which read struct frame should use the macros below */

/*
 * Overhead added to packet payload due to encapsulation
 */
#define EXTRA_FRAME(f)           ((f)->extra_frame)

/*
 * Delta between tun payload size and final TCP/UDP datagram size
 * (not including extra_link additions)
 */
#define TUN_LINK_DELTA(f)        ((f)->extra_frame + (f)->extra_tun)

/*
 * This is the maximum packet size that we need to be able to
 * read from or write to a tun or tap device.  For example,
 * a tap device ifconfiged to an MTU of 1200 might actually want
 * to return a packet size of 1214 on a read().
 */
#define PAYLOAD_SIZE(f)          ((f)->buf.payload_size)

/*
 * Max size of a payload packet after encryption, compression, etc.
 * overhead is added.
 */
#define EXPANDED_SIZE(f)         ((f)->link_mtu)
#define EXPANDED_SIZE_MIN(f)     (TUN_MTU_MIN + TUN_LINK_DELTA(f))

/*
 * Control buffer headroom allocations to allow for efficient prepending.
 */

/*
 * Max size of a buffer used to build a packet for output to
 * the TCP/UDP port or to read a packet from a tap/tun device.
 *
 * Most of our code only prepends headers but compression needs the extra bytes
 * *after* the data as compressed data might end up larger than the original
 * data (and max compression overhead is part of extra_buffer). Also crypto
 * needs an extra block for encryption. Therefore tailroom is larger than the
 * headroom.
 */
#define BUF_SIZE(f) ((f)->buf.headroom + (f)->buf.payload_size + (f)->buf.tailroom)

#define FRAME_HEADROOM(f)          ((f)->buf.headroom)

/*
 * Function prototypes.
 */

void frame_finalize(struct frame *frame,
                    bool link_mtu_defined,
                    int link_mtu,
                    bool tun_mtu_defined,
                    int tun_mtu);

void frame_subtract_extra(struct frame *frame, const struct frame *src);

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
frame_calculate_payload_overhead(const struct frame *frame,
                                 const struct options *options,
                                 const struct key_type *kt,
                                 bool extra_tun);

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
 * frame_set_mtu_dynamic and flags
 */

#define SET_MTU_TUN         (1<<0) /* use tun/tap rather than link sizing */
#define SET_MTU_UPPER_BOUND (1<<1) /* only decrease dynamic MTU */

void frame_set_mtu_dynamic(struct frame *frame, int mtu, unsigned int flags);

/*
 * allocate a buffer for socket or tun layer
 */
void alloc_buf_sock_tun(struct buffer *buf,
                        const struct frame *frame,
                        const bool tuntap_buffer);

/*
 * EXTENDED_SOCKET_ERROR_CAPABILITY functions -- print extra error info
 * on socket errors, such as PMTU size.  As of 2003.05.11, only works
 * on Linux 2.4+.
 */

#if EXTENDED_SOCKET_ERROR_CAPABILITY

void set_sock_extended_error_passing(int sd);

const char *format_extended_socket_error(int fd, int *mtu, struct gc_arena *gc);

#endif

/*
 * frame member adjustment functions
 */

static inline void
frame_add_to_link_mtu(struct frame *frame, const int increment)
{
    frame->link_mtu += increment;
}

static inline void
frame_add_to_extra_frame(struct frame *frame, const unsigned int increment)
{
    frame->extra_frame += increment;
}

static inline void
frame_remove_from_extra_frame(struct frame *frame, const unsigned int decrement)
{
    frame->extra_frame -= decrement;
}

static inline void
frame_add_to_extra_tun(struct frame *frame, const int increment)
{
    frame->extra_tun += increment;
}

static inline void
frame_add_to_extra_link(struct frame *frame, const int increment)
{
    frame->extra_link += increment;
}

static inline void
frame_add_to_extra_buffer(struct frame *frame, const int increment)
{
    frame->extra_buffer += increment;
}

static inline bool
frame_defined(const struct frame *frame)
{
    return frame->buf.payload_size > 0;
}

#endif /* ifndef MTU_H */
