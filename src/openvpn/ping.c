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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "ping.h"

#include "memdbg.h"


/*
 * This random string identifies an OpenVPN ping packet.
 * It should be of sufficient length and randomness
 * so as not to collide with other tunnel data.
 *
 * PING_STRING_SIZE must be sizeof (ping_string)
 */
const uint8_t ping_string[] = {
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
    0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

void
trigger_ping_timeout_signal(struct context *c)
{
    struct gc_arena gc = gc_new();
    switch (c->options.ping_rec_timeout_action)
    {
        case PING_EXIT:
            msg(M_INFO, "%sInactivity timeout (--ping-exit), exiting",
                format_common_name(c, &gc));
            c->sig->signal_received = SIGTERM;
            c->sig->signal_text = "ping-exit";
            break;

        case PING_RESTART:
            msg(M_INFO, "%sInactivity timeout (--ping-restart), restarting",
                format_common_name(c, &gc));
            c->sig->signal_received = SIGUSR1; /* SOFT-SIGUSR1 -- Ping Restart */
            c->sig->signal_text = "ping-restart";
            break;

        default:
            ASSERT(0);
    }
    gc_free(&gc);
}

/*
 * Should we ping the remote?
 */
void
check_ping_send_dowork(struct context *c)
{
    c->c2.buf = c->c2.buffers->aux_buf;
    ASSERT(buf_init(&c->c2.buf, FRAME_HEADROOM(&c->c2.frame)));
    ASSERT(buf_safe(&c->c2.buf, MAX_RW_SIZE_TUN(&c->c2.frame)));
    ASSERT(buf_write(&c->c2.buf, ping_string, sizeof(ping_string)));

    /*
     * We will treat the ping like any other outgoing packet,
     * encrypt, sign, etc.
     */
    encrypt_sign(c, true);
    /* Set length to 0, so it won't be counted as activity */
    c->c2.buf.len = 0;
    dmsg(D_PING, "SENT PING");
}
