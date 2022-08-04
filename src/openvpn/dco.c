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
#include "crypto.h"
#include "dco.h"
#include "errlevel.h"
#include "multi.h"
#include "networking.h"
#include "openvpn.h"
#include "options.h"
#include "ssl_common.h"
#include "ssl_ncp.h"
#include "tun.h"

static int
dco_install_key(struct tls_multi *multi, struct key_state *ks,
                const uint8_t *encrypt_key, const uint8_t *encrypt_iv,
                const uint8_t *decrypt_key, const uint8_t *decrypt_iv,
                const char *ciphername)

{
    msg(D_DCO_DEBUG, "%s: peer_id=%d keyid=%d", __func__, multi->peer_id,
        ks->key_id);

    /* Install a key in the PRIMARY slot only when no other key exist.
     * From that moment on, any new key will be installed in the SECONDARY
     * slot and will be promoted to PRIMARY when userspace says so (a swap
     * will be performed in that case)
     */
    dco_key_slot_t slot = OVPN_KEY_SLOT_PRIMARY;
    if (multi->dco_keys_installed > 0)
    {
        slot = OVPN_KEY_SLOT_SECONDARY;
    }

    int ret = dco_new_key(multi->dco, multi->peer_id, ks->key_id, slot,
                          encrypt_key, encrypt_iv,
                          decrypt_key, decrypt_iv,
                          ciphername);
    if ((ret == 0) && (multi->dco_keys_installed < 2))
    {
        multi->dco_keys_installed++;
        ks->dco_status = (slot == OVPN_KEY_SLOT_PRIMARY) ? DCO_INSTALLED_PRIMARY :
                         DCO_INSTALLED_SECONDARY;
    }

    return ret;
}

int
init_key_dco_bi(struct tls_multi *multi, struct key_state *ks,
                const struct key2 *key2, int key_direction,
                const char *ciphername, bool server)
{
    struct key_direction_state kds;
    key_direction_state_init(&kds, key_direction);

    return dco_install_key(multi, ks,
                           key2->keys[kds.out_key].cipher,
                           key2->keys[(int)server].hmac,
                           key2->keys[kds.in_key].cipher,
                           key2->keys[1 - (int)server].hmac,
                           ciphername);
}

/**
 * Find a usable key that is not the primary (i.e. the secondary key)
 *
 * @param multi     The TLS struct to retrieve keys from
 * @param primary   The primary key that should be skipped during the scan
 *
 * @return          The secondary key or NULL if none could be found
 */
static struct key_state *
dco_get_secondary_key(struct tls_multi *multi, const struct key_state *primary)
{
    for (int i = 0; i < KEY_SCAN_SIZE; ++i)
    {
        struct key_state *ks = get_key_scan(multi, i);
        struct key_ctx_bi *key = &ks->crypto_options.key_ctx_bi;

        if (ks == primary)
        {
            continue;
        }

        if (ks->state >= S_GENERATED_KEYS && ks->authenticated == KS_AUTH_TRUE)
        {
            ASSERT(key->initialized);
            return ks;
        }
    }

    return NULL;
}

void
dco_update_keys(dco_context_t *dco, struct tls_multi *multi)
{
    msg(D_DCO_DEBUG, "%s: peer_id=%d", __func__, multi->peer_id);

    /* this function checks if keys have to be swapped or erased, therefore it
     * can't do much if we don't have any key installed
     */
    if (multi->dco_keys_installed == 0)
    {
        return;
    }

    struct key_state *primary = tls_select_encryption_key(multi);
    /* no primary key available -> no usable key exists, therefore we should
     * tell DCO to simply wipe all keys
     */
    if (!primary)
    {
        msg(D_DCO, "No encryption key found. Purging data channel keys");

        int ret = dco_del_key(dco, multi->peer_id, OVPN_KEY_SLOT_PRIMARY);
        if (ret < 0)
        {
            msg(D_DCO, "Cannot delete primary key during wipe: %s (%d)", strerror(-ret), ret);
            return;
        }

        ret = dco_del_key(dco, multi->peer_id, OVPN_KEY_SLOT_SECONDARY);
        if (ret < 0)
        {
            msg(D_DCO, "Cannot delete secondary key during wipe: %s (%d)", strerror(-ret), ret);
            return;
        }

        multi->dco_keys_installed = 0;
        return;
    }

    /* if we have a primary key, it must have been installed already (keys
     * are installed upon generation in the TLS code)
     */
    ASSERT(primary->dco_status != DCO_NOT_INSTALLED);

    struct key_state *secondary = dco_get_secondary_key(multi, primary);
    /* if the current primary key was installed as secondary in DCO,
     * this means we have promoted it since installation in DCO, and
     * we now need to tell DCO to swap keys
     */
    if (primary->dco_status == DCO_INSTALLED_SECONDARY)
    {
        msg(D_DCO_DEBUG, "Swapping primary and secondary keys, now: id1=%d id2=%d",
            primary->key_id, secondary ? secondary->key_id : -1);

        int ret = dco_swap_keys(dco, multi->peer_id);
        if (ret < 0)
        {
            msg(D_DCO, "Cannot swap keys: %s (%d)", strerror(-ret), ret);
            return;
        }

        primary->dco_status = DCO_INSTALLED_PRIMARY;
        if (secondary)
        {
            ASSERT(secondary->dco_status == DCO_INSTALLED_PRIMARY);
            secondary->dco_status = DCO_INSTALLED_SECONDARY;
        }
    }

    /* if we have no secondary key anymore, inform DCO about it */
    if (!secondary && multi->dco_keys_installed == 2)
    {
        int ret = dco_del_key(dco, multi->peer_id, OVPN_KEY_SLOT_SECONDARY);
        if (ret < 0)
        {
            msg(D_DCO, "Cannot delete secondary key: %s (%d)", strerror(-ret), ret);
            return;
        }
        multi->dco_keys_installed = 1;
    }

    /* all keys that are not installed are set to NOT installed */
    for (int i = 0; i < KEY_SCAN_SIZE; ++i)
    {
        struct key_state *ks = get_key_scan(multi, i);
        if (ks != primary && ks != secondary)
        {
            ks->dco_status = DCO_NOT_INSTALLED;
        }
    }
}

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

    if (!o->dev)
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

bool
dco_check_pull_options(int msglevel, const struct options *o)
{
    if (!o->use_peer_id)
    {
        msg(msglevel, "OPTIONS IMPORT: Server did not request DATA_V2 packet "
            "format required for data channel offload");
        return false;
    }
    return true;
}

int
dco_p2p_add_new_peer(struct context *c)
{
    if (!dco_enabled(&c->options))
    {
        return 0;
    }

    struct tls_multi *multi = c->c2.tls_multi;
    struct link_socket *ls = c->c2.link_socket;

    struct in6_addr remote_ip6 = { 0 };
    struct in_addr remote_ip4 = { 0 };

    struct in6_addr *remote_addr6 = NULL;
    struct in_addr *remote_addr4 = NULL;

    const char *gw = NULL;

    ASSERT(ls->info.connection_established);

    /* In client mode if a P2P style topology is used we assume the
     * remote-gateway is the IP of the peer */
    if (c->options.topology == TOP_NET30 || c->options.topology == TOP_P2P)
    {
        gw = c->options.ifconfig_remote_netmask;
    }
    if (c->options.route_default_gateway)
    {
        gw = c->options.route_default_gateway;
    }

    /* These inet_pton conversion are fatal since options.c already implements
     * checks to have only valid addresses when setting the options */
    if (c->options.ifconfig_ipv6_remote)
    {
        if (inet_pton(AF_INET6, c->options.ifconfig_ipv6_remote, &remote_ip6) != 1)
        {
            msg(M_FATAL,
                "DCO peer init: problem converting IPv6 ifconfig remote address %s to binary",
                c->options.ifconfig_ipv6_remote);
        }
        remote_addr6 = &remote_ip6;
    }

    if (gw)
    {
        if (inet_pton(AF_INET, gw, &remote_ip4) != 1)
        {
            msg(M_FATAL, "DCO peer init: problem converting IPv4 ifconfig gateway address %s to binary", gw);
        }
        remote_addr4 = &remote_ip4;
    }
    else if (c->options.ifconfig_local)
    {
        msg(M_INFO, "DCO peer init: Need a peer VPN addresss to setup IPv4 (set --route-gateway)");
    }

    struct sockaddr *remoteaddr = &ls->info.lsa->actual.dest.addr.sa;

    int ret = dco_new_peer(&c->c1.tuntap->dco, multi->peer_id,
                           c->c2.link_socket->sd, NULL, remoteaddr,
                           remote_addr4, remote_addr6);
    if (ret < 0)
    {
        return ret;
    }

    c->c2.tls_multi->dco_peer_added = true;
    c->c2.link_socket->info.dco_installed = true;

    return 0;
}

void
dco_remove_peer(struct context *c)
{
    if (!dco_enabled(&c->options))
    {
        return;
    }

    if (c->c1.tuntap && c->c2.tls_multi && c->c2.tls_multi->dco_peer_added)
    {
        dco_del_peer(&c->c1.tuntap->dco, c->c2.tls_multi->peer_id);
        c->c2.tls_multi->dco_peer_added = false;
    }
}

#endif /* defined(ENABLE_DCO) */
