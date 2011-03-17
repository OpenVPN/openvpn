/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

/*
 * Each session is identified by a random 8-byte session identifier.
 *
 * For efficiency, the session id is only transmitted over the control
 * channel (which only sees traffic occasionally when keys are being
 * negotiated).  The data channel sees a smaller version of the session-id --
 * it is called the key_id and is currently 2 bits long.
 */

#include "syshead.h"

#if defined(USE_CRYPTO) && defined(USE_SSL)

#include "error.h"
#include "common.h"
#include "crypto.h"
#include "session_id.h"

#include "memdbg.h"

const struct session_id x_session_id_zero;

void
session_id_random (struct session_id *sid)
{
  prng_bytes (sid->id, SID_SIZE);
}

const char *
session_id_print (const struct session_id *sid, struct gc_arena *gc)
{
  return format_hex (sid->id, SID_SIZE, 0, gc);
}

#else
static void dummy(void) {}
#endif /* USE_CRYPTO && USE_SSL*/
