/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

/*
 * Each session is identified by a random 8-byte session identifier.
 *
 * For efficiency, the session id is only transmitted over the control
 * channel (which only sees traffic occasionally when keys are being
 * negotiated).
 */

#ifndef SESSION_ID_H
#define SESSION_ID_H

#include "basic.h"
#include "buffer.h"

struct session_id
{
    uint8_t id[8];
};

extern const struct session_id x_session_id_zero;

#define SID_SIZE (sizeof(x_session_id_zero.id))

static inline bool
session_id_equal(const struct session_id *sid1,
                 const struct session_id *sid2)
{
    return !memcmp(sid1->id, sid2->id, SID_SIZE);
}

static inline bool
session_id_defined(const struct session_id *sid1)
{
    return memcmp(sid1->id, &x_session_id_zero.id, SID_SIZE) != 0;
}

static inline bool
session_id_read(struct session_id *sid, struct buffer *buf)
{
    return buf_read(buf, sid->id, SID_SIZE);
}

static inline bool
session_id_write_prepend(const struct session_id *sid, struct buffer *buf)
{
    return buf_write_prepend(buf, sid->id, SID_SIZE);
}

static inline bool
session_id_write(const struct session_id *sid, struct buffer *buf)
{
    return buf_write(buf, sid->id, SID_SIZE);
}

void session_id_random(struct session_id *sid);

const char *session_id_print(const struct session_id *sid, struct gc_arena *gc);

#endif /* SESSION_ID_H */
