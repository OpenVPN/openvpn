/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
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
 * Encoding and decoding of the server probe TLVs.
 *
 * A client probes a server by sending a P_CONTROL_V2 message whose payload
 * carries a probe request TLV, and the server answers with a P_CONTROL_V2
 * message carrying a probe reply TLV. The reply tells the client how the
 * server wants to be ranked against the other remotes, and can also serve
 * as the second packet of the three-way handshake.
 *
 * The TLV framing and the TLV type space are shared with the other TLV-based
 * control messages and live in control_msg.h; this file holds the two probe
 * TLVs and what their fields mean.
 */

#ifndef PROBE_H
#define PROBE_H

#include "buffer.h"
#include "control_msg.h"

/** probe request flags. The client is only probing: it does not want to
 * continue into a handshake, and the server may forget it right away. */
#define PROBE_REQUEST_FLAG_PROBE_ONLY 0x00000001

/* probe reply flags */
/** complete the handshake with P_CONTROL_WKC_V1 rather than P_CONTROL_V1 */
#define PROBE_REPLY_FLAG_RESEND_WKC      0x0001
/** the other addresses of this remote are the same server, no need to probe them */
#define PROBE_REPLY_FLAG_ADDRS_EQUAL     0x0002
/** the connect_lifetime holds against those other addresses too, so a reply
 * from one of them can skip the handshake with another. Only meaningful
 * together with ADDRS_EQUAL, which is what names those addresses. */
#define PROBE_REPLY_FLAG_LIFETIME_SHARED 0x0004
/** the other addresses of this remote are distinct servers, so probe them too */
#define PROBE_REPLY_FLAG_PROBE_MORE      0x0008

/** probe request TLV, sent by a client to probe a server */
struct probe_request
{
    uint64_t request_id; /**< identifies this probe, echoed in the reply */
    /** The client clock as a UNIX timestamp in seconds. It is there for the
     * server, which uses it to bound how old a request it will answer and so
     * how long a captured one can be replayed. The reply does not echo it: a
     * client times the round trip itself, by the request_id. */
    uint64_t timestamp;
    uint32_t flags; /**< PROBE_REQUEST_FLAG_* */
};

/** probe reply TLV, a server's answer to a probe request */
struct probe_reply
{
    uint64_t request_id;       /**< echoes the request_id of the request */
    uint16_t priority;         /**< DNS SRV style priority, lower is preferred */
    uint16_t weight;           /**< DNS SRV style weight */
    uint16_t max_latency_diff; /**< candidate band in ms around the fastest server */
    /** For how many seconds, counted from the moment the client sent its own
     * probe request, the server will still treat this exchange as the first
     * two packets of the handshake. Within that window the client may send the
     * third packet straight away instead of starting a handshake of its own.
     * 0 means it cannot, so it has to begin a fresh one. */
    uint16_t connect_lifetime;
    uint16_t flags; /**< PROBE_REPLY_FLAG_* */
};

/* Smallest on-wire value length (the TLV header not counted) of each TLV: the
 * sizes of the fixed fields above, in wire order. A value may be longer, which
 * is how the TLVs are extended; trailing bytes that are not understood are
 * ignored on read. */

/** request_id (u64), timestamp (u64), flags (u32) */
#define PROBE_REQUEST_LEN ((uint16_t)(2 * sizeof(uint64_t) + sizeof(uint32_t)))

/** request_id (u64), then priority, weight, max_latency_diff,
 * connect_lifetime and flags (u16 each) */
#define PROBE_REPLY_LEN ((uint16_t)(sizeof(uint64_t) + 5 * sizeof(uint16_t)))

/**
 * Write a complete probe request TLV, header and value, to buf.
 *
 * @return true on success, false if buf has insufficient space.
 */
bool probe_request_write(struct buffer *buf, const struct probe_request *r);

/**
 * Read a probe request TLV value from buf.
 *
 * buf must cover exactly the TLV's value, as ctrl_msg_find_tlv() returns it.
 * Bytes beyond the fields understood here are ignored, so a longer value from
 * a future version still parses. Flag bits that are not known are kept in
 * flags rather than rejected, for the same reason.
 *
 * @return true on success, false if buf is shorter than the mandatory fields.
 */
bool probe_request_read(struct buffer *buf, struct probe_request *r);

/**
 * Write a complete probe reply TLV, header and value, to buf.
 *
 * @return true on success, false if buf has insufficient space.
 */
bool probe_reply_write(struct buffer *buf, const struct probe_reply *r);

/**
 * Read a probe reply TLV value from buf. The calling convention is that of
 * probe_request_read().
 *
 * The two flag combinations the protocol rules out are rejected here, since
 * neither can be acted on: a reply must not call the other addresses of the
 * remote both the same server and distinct ones, and it must not extend the
 * connect_lifetime to those addresses without first calling them the same
 * server.
 *
 * @return true on success, false if buf is shorter than the mandatory fields
 *         or the flags contradict each other.
 */
bool probe_reply_read(struct buffer *buf, struct probe_reply *r);

#endif /* ifndef PROBE_H */
