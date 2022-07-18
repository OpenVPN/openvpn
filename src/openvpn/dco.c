/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2021-2022 Arne Schwabe <arne@rfc2549.org>
 *  Copyright (C) 2021-2022 Antonio Quartulli <a@unstable.cc>
 *  Copyright (C) 2021-2022 OpenVPN Inc <sales@openvpn.net>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#if defined(ENABLE_DCO)

#include "syshead.h"
#include "dco.h"
#include "networking.h"
#include "options.h"
#include "ssl_ncp.h"
#include "tun.h"

static bool
dco_check_option_conflict_platform(int msglevel, const struct options *o)
{
#if defined(TARGET_LINUX)
    /* if the device name is fixed, we need to check if an interface with this
     * name already exists. IF it does, it must be a DCO interface, otherwise
     * DCO has to be disabled in order to continue.
     */
    if (tun_name_is_fixed(o->dev))
    {
        char iftype[IFACE_TYPE_LEN_MAX];
        /* we pass NULL as net_ctx because using DCO on Linux implies that we
         * are using SITNL and the latter does not need any context. This way we
         * don't need to have the net_ctx percolate all the way here
         */
        int ret = net_iface_type(NULL, o->dev, iftype);
        if ((ret == 0) && (strcmp(iftype, "ovpn-dco") != 0))
        {
            msg(msglevel, "Interface %s exists and is non-DCO. Disabling data channel offload",
                o->dev);
            return false;
        }
        else if ((ret < 0) && (ret != -ENODEV))
        {
            msg(msglevel, "Cannot retrieve type of device %s: %s (%d)", o->dev,
                strerror(-ret), ret);
        }
    }
#endif /* if defined(TARGET_LINUX) */
    return true;
}

static bool
dco_check_option_conflict_ce(const struct connection_entry *ce, int msglevel)
{
    if (ce->fragment)
    {
        msg(msglevel, "Note: --fragment disables data channel offload.");
        return false;
    }

    if (ce->http_proxy_options)
    {
        msg(msglevel, "Note: --http-proxy disables data channel offload.");
        return false;
    }

    if (ce->socks_proxy_server)
    {
        msg(msglevel, "Note: --socks-proxy disables data channel offload.");
        return false;
    }

    return true;
}

bool
dco_check_option_conflict(int msglevel, const struct options *o)
{
    if (o->tuntap_options.disable_dco)
    {
        /* already disabled by --disable-dco, no need to print warnings */
        return false;
    }

    if (!dco_available(msglevel))
    {
        return false;
    }

    if (!dco_check_option_conflict_platform(msglevel, o))
    {
        return false;
    }

    if (dev_type_enum(o->dev, o->dev_type) != DEV_TYPE_TUN)
    {
        msg(msglevel, "Note: dev-type not tun, disabling data channel offload.");
        return false;
    }

    /* At this point the ciphers have already been normalised */
    if (o->enable_ncp_fallback
        && !tls_item_in_cipher_list(o->ciphername, DCO_SUPPORTED_CIPHERS))
    {
        msg(msglevel, "Note: --data-cipher-fallback with cipher '%s' "
            "disables data channel offload.", o->ciphername);
        return false;
    }

    if (o->connection_list)
    {
        const struct connection_list *l = o->connection_list;
        for (int i = 0; i < l->len; ++i)
        {
            if (!dco_check_option_conflict_ce(l->array[i], msglevel))
            {
                return false;
            }
        }
    }
    else
    {
        if (!dco_check_option_conflict_ce(&o->ce, msglevel))
        {
            return false;
        }
    }

    if (o->mode == MODE_SERVER && o->topology != TOP_SUBNET)
    {
        msg(msglevel, "Note: NOT using '--topology subnet' disables data channel offload.");
        return false;
    }

#if defined(USE_COMP)
    if (o->comp.alg != COMP_ALG_UNDEF)
    {
        msg(msglevel, "Note: Using compression disables data channel offload.");

        if (o->mode == MODE_SERVER && !(o->comp.flags & COMP_F_MIGRATE))
        {
            /* We can end up here from the multi.c call, only print the
             * note if it is not already enabled */
            msg(msglevel, "Consider using the '--compress migrate' option.");
        }
        return false;
    }
#endif

    struct gc_arena gc = gc_new();
    char *tmp_ciphers = string_alloc(o->ncp_ciphers, &gc);
    const char *token;
    while ((token = strsep(&tmp_ciphers, ":")))
    {
        if (!tls_item_in_cipher_list(token, DCO_SUPPORTED_CIPHERS))
        {
            msg(msglevel, "Note: cipher '%s' in --data-ciphers is not supported "
                "by ovpn-dco, disabling data channel offload.", token);
            gc_free(&gc);
            return false;
        }
    }
    gc_free(&gc);

    return true;
}

#endif /* defined(ENABLE_DCO) */
