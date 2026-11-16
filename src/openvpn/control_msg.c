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

#include "control_msg.h"

bool
ctrl_msg_tlv_write_header(struct buffer *buf, uint16_t type, bool optional, uint16_t value_len)
{
    /* the type has 15 bits; the top bit is the optional flag */
    ASSERT(type <= CTRL_MSG_TLV_TYPE_MASK);

    /* Write nothing unless the whole TLV fits. The header promises that
     * value_len bytes follow it, so a header written without room for the
     * value would leave a partial TLV in buf. */
    if (!buf_safe(buf, (size_t)CTRL_MSG_TLV_HEADER_LEN + value_len))
    {
        return false;
    }
    uint16_t field = type;
    if (optional)
    {
        field |= CTRL_MSG_TLV_OPTIONAL_FLAG;
    }
    return buf_write_u16(buf, field) && buf_write_u16(buf, value_len);
}

bool
ctrl_msg_tlv_write_u16(struct buffer *buf, uint16_t type, bool optional, uint16_t value)
{
    return ctrl_msg_tlv_write_header(buf, type, optional, sizeof(uint16_t))
           && buf_write_u16(buf, value);
}

bool
ctrl_msg_tlv_peek_header(const struct buffer *buf, struct ctrl_msg_tlv_header *hdr)
{
    if (BLEN(buf) < CTRL_MSG_TLV_HEADER_LEN)
    {
        return false; /* fewer than 4 bytes left: truncated header */
    }
    /* read from a copy, so that buf is left where it was */
    struct buffer tmp = *buf;
    uint16_t field = (uint16_t)buf_read_u16(&tmp);
    hdr->value_len = (uint16_t)buf_read_u16(&tmp);
    hdr->type = field & CTRL_MSG_TLV_TYPE_MASK;
    hdr->optional = (field & CTRL_MSG_TLV_OPTIONAL_FLAG) != 0;
    return true;
}

bool
ctrl_msg_tlv_next(struct buffer *buf, struct ctrl_msg_tlv_header *hdr, struct buffer *value)
{
    if (!ctrl_msg_tlv_peek_header(buf, hdr))
    {
        return false;
    }
    /* Consume nothing unless the whole TLV is there, so that a value shorter
     * than the header claims leaves buf untouched. */
    if (BLEN(buf) < CTRL_MSG_TLV_HEADER_LEN + hdr->value_len)
    {
        return false;
    }
    ASSERT(buf_advance(buf, CTRL_MSG_TLV_HEADER_LEN));
    const uint8_t *v = buf_read_alloc(buf, hdr->value_len);
    ASSERT(v);
    buf_set_read(value, v, hdr->value_len);
    return true;
}
