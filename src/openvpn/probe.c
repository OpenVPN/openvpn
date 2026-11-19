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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "probe.h"
#include "control_msg.h"

bool
probe_request_write(struct buffer *buf, const struct probe_request *r)
{
    return ctrl_msg_tlv_write_header(buf, TLV_TYPE_PROBE_REQUEST, false, PROBE_REQUEST_LEN)
           && buf_write_u64(buf, r->request_id) && buf_write_u64(buf, r->timestamp)
           && buf_write_u32(buf, r->flags);
}

bool
probe_request_read(struct buffer *buf, struct probe_request *r)
{
    /* One bounds check covers the whole value: every field read below then fits
     * by construction, PROBE_REQUEST_LEN being the sum of their sizes, so none
     * of them needs its own error handling. Trailing bytes this version does
     * not understand are simply left unread. */
    if (buf_len(buf) < PROBE_REQUEST_LEN)
    {
        return false;
    }
    r->request_id = buf_read_u64(buf, NULL);
    r->timestamp = buf_read_u64(buf, NULL);
    r->flags = buf_read_u32(buf, NULL);
    return true;
}

bool
probe_reply_write(struct buffer *buf, const struct probe_reply *r)
{
    return ctrl_msg_tlv_write_header(buf, TLV_TYPE_PROBE_REPLY, false, PROBE_REPLY_LEN)
           && buf_write_u64(buf, r->request_id) && buf_write_u16(buf, r->priority)
           && buf_write_u16(buf, r->weight) && buf_write_u16(buf, r->max_latency_diff)
           && buf_write_u16(buf, r->connect_lifetime) && buf_write_u16(buf, r->flags);
}

bool
probe_reply_read(struct buffer *buf, struct probe_reply *r)
{
    /* One bounds check for the whole value, as in probe_request_read(). */
    if (buf_len(buf) < PROBE_REPLY_LEN)
    {
        return false;
    }
    r->request_id = buf_read_u64(buf, NULL);
    r->priority = (uint16_t)buf_read_u16(buf);
    r->weight = (uint16_t)buf_read_u16(buf);
    r->max_latency_diff = (uint16_t)buf_read_u16(buf);
    r->connect_lifetime = (uint16_t)buf_read_u16(buf);
    r->flags = (uint16_t)buf_read_u16(buf);

    /* The other addresses of the remote cannot be both the same server and
     * distinct ones. And LIFETIME_SHARED extends the connect_lifetime to those
     * other addresses, which says nothing unless ADDRS_EQUAL has declared them
     * the same server to begin with. */
    if ((r->flags & PROBE_REPLY_FLAG_ADDRS_EQUAL) && (r->flags & PROBE_REPLY_FLAG_PROBE_MORE))
    {
        return false;
    }
    if ((r->flags & PROBE_REPLY_FLAG_LIFETIME_SHARED) && !(r->flags & PROBE_REPLY_FLAG_ADDRS_EQUAL))
    {
        return false;
    }
    return true;
}
