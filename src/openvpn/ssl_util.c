/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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
#endif

#include "syshead.h"

#include "ssl_util.h"

char *
extract_var_peer_info(const char *peer_info, const char *var,
                      struct gc_arena *gc)
{
    if (!peer_info)
    {
        return NULL;
    }

    const char *var_start = strstr(peer_info, var);
    if (!var_start)
    {
        /* variable not found in peer info */
        return NULL;
    }

    var_start += strlen(var);
    const char *var_end = strstr(var_start, "\n");
    if (!var_end)
    {
        /* var is at end of the peer_info list and no '\n' follows */
        var_end = var_start + strlen(var_start);
    }

    char *var_value = string_alloc(var_start, gc);
    /* NULL terminate the copy at the right position */
    var_value[var_end - var_start] = '\0';
    return var_value;
}

unsigned int
extract_iv_proto(const char *peer_info)
{
    const char *optstr = peer_info ? strstr(peer_info, "IV_PROTO=") : NULL;
    if (optstr)
    {
        int proto = 0;
        int r = sscanf(optstr, "IV_PROTO=%d", &proto);
        if (r == 1 && proto > 0)
        {
            return proto;
        }
    }
    return 0;
}

const char *
options_string_compat_lzo(const char *options, struct gc_arena *gc)
{
    /* Example string without and with comp-lzo, i.e. input/output of this function */
    /* w/o comp: 'V4,dev-type tun,link-mtu 1457,tun-mtu 1400,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-server' */
    /* comp-lzo: 'V4,dev-type tun,link-mtu 1458,tun-mtu 1400,proto UDPv4,comp-lzo,auth SHA1,keysize 128,key-method 2,tls-server' */

    /* Note: since this function is used only in a very limited scope it makes
     * assumptions how the string looks. Since we locally generated the string
     * we can make these assumptions */

    /* Check that the link-mtu string is in options */
    const char *tmp = strstr(options, ",link-mtu");
    if (!tmp)
    {
        return options;
    }

    /* Get old link_mtu size */
    int link_mtu;
    if (sscanf(tmp, ",link-mtu %d,", &link_mtu) != 1 || link_mtu < 100 || link_mtu > 9900)
    {
        return options;
    }

    /* 1 byte for the possibility of 999 to 1000 and 1 byte for the null
     * terminator */
    struct buffer buf = alloc_buf_gc(strlen(options) + strlen(",comp-lzo") + 2, gc);

    buf_write(&buf, options, (int)(tmp - options));

    /* Increase link-mtu by one for the comp-lzo opcode */
    buf_printf(&buf, ",link-mtu %d", link_mtu + 1);

    tmp += strlen(",link-mtu ") + (link_mtu < 1000 ? 3 : 4);

    buf_printf(&buf, "%s,comp-lzo", tmp);

    return BSTR(&buf);
}
