/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2021-2023 Arne Schwabe <arne@rfc2549.org>
 *  Copyright (C) 2021-2023 Antonio Quartulli <a@unstable.cc>
 *  Copyright (C) 2021-2023 OpenVPN Inc <sales@openvpn.net>
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

#ifdef HAVE_LIBCAPNG
#include <cap-ng.h>
#endif

static int
dco_install_key(struct tls_multi *multi, struct key_state *ks,
                const uint8_t *encrypt_key, const uint8_t *encrypt_iv,
                const uint8_t *decrypt_key, const uint8_t *decrypt_iv,
                const char *ciphername)

{
    msg(D_DCO_DEBUG, "%s: peer_id=%d keyid=%d, currently %d keys installed",
        __func__, multi->dco_peer_id, ks->key_id, multi->dco_keys_installed);

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

    int ret = dco_new_key(multi->dco, multi->dco_peer_id, ks->key_id, slot,
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

bool
dco_update_keys(dco_context_t *dco, struct tls_multi *multi)
{
    /* this function checks if keys have to be swapped or erased, therefore it
     * can't do much if we don't have any key installed
     */
    if (multi->dco_keys_installed == 0)
    {
        return true;
    }

    struct key_state *primary = tls_select_encryption_key(multi);
    /* no primary key available -> no usable key exists, therefore we should
     * tell DCO to simply wipe all keys
     */
    if (!primary)
    {
        msg(D_DCO, "No encryption key found. Purging data channel keys");

        int ret = dco_del_key(dco, multi->dco_peer_id, OVPN_KEY_SLOT_PRIMARY);
        if (ret < 0)
        {
            msg(D_DCO, "Cannot delete primary key during wipe: %s (%d)", strerror(-ret), ret);
            return false;
        }

        ret = dco_del_key(dco, multi->dco_peer_id, OVPN_KEY_SLOT_SECONDARY);
        if (ret < 0)
        {
            msg(D_DCO, "Cannot delete secondary key during wipe: %s (%d)", strerror(-ret), ret);
            return false;
        }

        multi->dco_keys_installed = 0;
        return true;
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
        if (secondary)
        {
            msg(D_DCO_DEBUG, "Swapping primary and secondary keys to "
                "primary-id=%d secondary-id=%d",
                primary->key_id, secondary->key_id);
        }
        else
        {
            msg(D_DCO_DEBUG, "Swapping primary and secondary keys to"
                "primary-id=%d secondary-id=(to be deleted)",
                primary->key_id);
        }

        int ret = dco_swap_keys(dco, multi->dco_peer_id);
        if (ret < 0)
        {
            msg(D_DCO, "Cannot swap keys: %s (%d)", strerror(-ret), ret);
            return false;
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
        int ret = dco_del_key(dco, multi->dco_peer_id, OVPN_KEY_SLOT_SECONDARY);
        if (ret < 0)
        {
            msg(D_DCO, "Cannot delete secondary key: %s (%d)", strerror(-ret), ret);
            return false;
        }
        multi->dco_keys_installed = 1;
    }

    /* all keys that are not installed are set to NOT installed. Include also
     * keys that might even be considered as active keys to be sure*/
    for (int i = 0; i < TM_SIZE; ++i)
    {
        for (int j = 0; j < KS_SIZE; j++)
        {
            struct key_state *ks = &multi->session[i].key[j];
            if (ks != primary && ks != secondary)
            {
                ks->dco_status = DCO_NOT_INSTALLED;
            }
        }
    }
    return true;
}

static bool
dco_check_option_ce(const struct connection_entry *ce, int msglevel)
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

#if defined(TARGET_FREEBSD)
    if (!proto_is_udp(ce->proto))
    {
        msg(msglevel, "NOTE: TCP transport disables data channel offload on FreeBSD.");
        return false;
    }
#endif

#if defined(_WIN32)
    if (!ce->remote)
    {
        msg(msglevel, "NOTE: --remote is not defined, disabling data channel offload.");
        return false;
    }
#endif

    return true;
}

bool
dco_check_startup_option(int msglevel, const struct options *o)
{
    /* check if no dev name was specified at all. In the case,
     * later logic will most likely stop OpenVPN, so no need to
     * print any message here.
     */
    if (!o->dev)
    {
        return false;
    }

    if (!o->tls_client && !o->tls_server)
    {
        msg(msglevel, "No tls-client or tls-server option in configuration "
            "detected. Disabling data channel offload.");
        return false;
    }

    if (dev_type_enum(o->dev, o->dev_type) != DEV_TYPE_TUN)
    {
        msg(msglevel, "Note: dev-type not tun, disabling data channel offload.");
        return false;
    }

    if (o->connection_list)
    {
        const struct connection_list *l = o->connection_list;
        for (int i = 0; i < l->len; ++i)
        {
            if (!dco_check_option_ce(l->array[i], msglevel))
            {
                return false;
            }
        }
    }
    else
    {
        if (!dco_check_option_ce(&o->ce, msglevel))
        {
            return false;
        }
    }

#if defined(_WIN32)
    if (o->mode == MODE_SERVER)
    {
        msg(msglevel, "--mode server is set. Disabling Data Channel Offload");
        return false;
    }

    if ((o->windows_driver == WINDOWS_DRIVER_WINTUN)
        || (o->windows_driver == WINDOWS_DRIVER_TAP_WINDOWS6))
    {
        msg(msglevel, "--windows-driver is set to '%s'. Disabling Data Channel Offload",
            print_windows_driver(o->windows_driver));
        return false;
    }

#elif defined(TARGET_LINUX)
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
#endif /* if defined(_WIN32) */

#if defined(HAVE_LIBCAPNG)
    /* DCO can't operate without CAP_NET_ADMIN. To retain it when switching user
     * we need CAP_SETPCAP. CAP_NET_ADMIN also needs to be part of the permitted set
     * of capabilities in order to retain it.
     */
    if (o->username)
    {
        if (!capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP))
        {
            msg(msglevel, "--user specified but lacking CAP_SETPCAP. "
                "Cannot retain CAP_NET_ADMIN. Disabling data channel offload");
            return false;
        }
        if (!capng_have_capability(CAPNG_PERMITTED, CAP_NET_ADMIN))
        {
            msg(msglevel, "--user specified but not permitted to retain CAP_NET_ADMIN. "
                "Disabling data channel offload");
            return false;
        }
    }
#endif /* if defined(HAVE_LIBCAPNG) */

    if (o->mode == MODE_SERVER && o->topology != TOP_SUBNET)
    {
        msg(msglevel, "Note: NOT using '--topology subnet' disables data channel offload.");
        return false;
    }

    /* now that all options have been confirmed to be supported, check
     * if DCO is truly available on the system
     */
    return dco_available(msglevel);
}

bool
dco_check_option(int msglevel, const struct options *o)
{
    /* At this point the ciphers have already been normalised */
    if (o->enable_ncp_fallback
        && !tls_item_in_cipher_list(o->ciphername, dco_get_supported_ciphers()))
    {
        msg(msglevel, "Note: --data-cipher-fallback with cipher '%s' "
            "disables data channel offload.", o->ciphername);
        return false;
    }

#if defined(USE_COMP)
    if (o->comp.alg != COMP_ALG_UNDEF
        || o->comp.flags & COMP_F_ALLOW_ASYM
        || o->comp.flags & COMP_F_ALLOW_COMPRESS)
    {
        msg(msglevel, "Note: '--allow-compression' is not set to 'no', disabling data channel offload.");

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
        if (!tls_item_in_cipher_list(token, dco_get_supported_ciphers()))
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

    struct link_socket *ls = c->c2.link_socket;

    ASSERT(ls->info.connection_established);

    struct sockaddr *remoteaddr = &ls->info.lsa->actual.dest.addr.sa;
    struct tls_multi *multi = c->c2.tls_multi;
#ifdef TARGET_FREEBSD
    /* In Linux in P2P mode the kernel automatically removes an existing peer
     * when adding a new peer. FreeBSD needs to explicitly be told to do that */
    if (c->c2.tls_multi->dco_peer_id != -1)
    {
        dco_del_peer(&c->c1.tuntap->dco, c->c2.tls_multi->dco_peer_id);
        c->c2.tls_multi->dco_peer_id = -1;
    }
#endif
    int ret = dco_new_peer(&c->c1.tuntap->dco, multi->peer_id,
                           c->c2.link_socket->sd, NULL, remoteaddr, NULL, NULL);
    if (ret < 0)
    {
        return ret;
    }

    c->c2.tls_multi->dco_peer_id = multi->peer_id;

    return 0;
}

void
dco_remove_peer(struct context *c)
{
    if (!dco_enabled(&c->options))
    {
        return;
    }

    if (c->c1.tuntap && c->c2.tls_multi && c->c2.tls_multi->dco_peer_id != -1)
    {
        dco_del_peer(&c->c1.tuntap->dco, c->c2.tls_multi->dco_peer_id);
        c->c2.tls_multi->dco_peer_id = -1;
    }
}

static bool
dco_multi_get_localaddr(struct multi_context *m, struct multi_instance *mi,
                        struct sockaddr_storage *local)
{
#if ENABLE_IP_PKTINFO
    struct context *c = &mi->context;

    if (!(c->options.sockflags & SF_USE_IP_PKTINFO))
    {
        return false;
    }

    struct link_socket_actual *actual = &c->c2.link_socket_info->lsa->actual;

    switch (actual->dest.addr.sa.sa_family)
    {
        case AF_INET:
        {
            struct sockaddr_in *sock_in4 = (struct sockaddr_in *)local;
#if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST)
            sock_in4->sin_addr = actual->pi.in4.ipi_addr;
#elif defined(IP_RECVDSTADDR)
            sock_in4->sin_addr = actual->pi.in4;
#else
            /* source IP not available on this platform */
            return false;
#endif
            sock_in4->sin_family = AF_INET;
            break;
        }

        case AF_INET6:
        {
            struct sockaddr_in6 *sock_in6 = (struct sockaddr_in6 *)local;
            sock_in6->sin6_addr = actual->pi.in6.ipi6_addr;
            sock_in6->sin6_family = AF_INET6;
            break;
        }

        default:
            ASSERT(false);
    }

    return true;
#else  /* if ENABLE_IP_PKTINFO */
    return false;
#endif /* if ENABLE_IP_PKTINFO */
}

int
dco_multi_add_new_peer(struct multi_context *m, struct multi_instance *mi)
{
    struct context *c = &mi->context;

    int peer_id = c->c2.tls_multi->peer_id;
    struct sockaddr *remoteaddr, *localaddr = NULL;
    struct sockaddr_storage local = { 0 };
    int sd = c->c2.link_socket->sd;


    if (c->mode == CM_CHILD_TCP)
    {
        /* the remote address will be inferred from the TCP socket endpoint */
        remoteaddr = NULL;
    }
    else
    {
        ASSERT(c->c2.link_socket_info->connection_established);
        remoteaddr = &c->c2.link_socket_info->lsa->actual.dest.addr.sa;
    }

    /* In server mode we need to fetch the remote addresses from the push config */
    struct in_addr vpn_ip4 = { 0 };
    struct in_addr *vpn_addr4 = NULL;
    if (c->c2.push_ifconfig_defined)
    {
        vpn_ip4.s_addr = htonl(c->c2.push_ifconfig_local);
        vpn_addr4 = &vpn_ip4;
    }

    struct in6_addr *vpn_addr6 = NULL;
    if (c->c2.push_ifconfig_ipv6_defined)
    {
        vpn_addr6 = &c->c2.push_ifconfig_ipv6_local;
    }

    if (dco_multi_get_localaddr(m, mi, &local))
    {
        localaddr = (struct sockaddr *)&local;
    }

    int ret = dco_new_peer(&c->c1.tuntap->dco, peer_id, sd, localaddr,
                           remoteaddr, vpn_addr4, vpn_addr6);
    if (ret < 0)
    {
        return ret;
    }

    c->c2.tls_multi->dco_peer_id = peer_id;

    return 0;
}

void
dco_install_iroute(struct multi_context *m, struct multi_instance *mi,
                   struct mroute_addr *addr)
{
#if defined(TARGET_LINUX) || defined(TARGET_FREEBSD)
    if (!dco_enabled(&m->top.options))
    {
        return;
    }

    int addrtype = (addr->type & MR_ADDR_MASK);

    /* If we do not have local IP addr to install, skip the route */
    if ((addrtype == MR_ADDR_IPV6 && !mi->context.c2.push_ifconfig_ipv6_defined)
        || (addrtype == MR_ADDR_IPV4 && !mi->context.c2.push_ifconfig_defined))
    {
        return;
    }

    struct context *c = &mi->context;
    const char *dev = c->c1.tuntap->actual_name;

    if (addrtype == MR_ADDR_IPV6)
    {
        net_route_v6_add(&m->top.net_ctx, &addr->v6.addr, addr->netbits,
                         &mi->context.c2.push_ifconfig_ipv6_local, dev, 0,
                         DCO_IROUTE_METRIC);
    }
    else if (addrtype == MR_ADDR_IPV4)
    {
        in_addr_t dest = htonl(addr->v4.addr);
        net_route_v4_add(&m->top.net_ctx, &dest, addr->netbits,
                         &mi->context.c2.push_ifconfig_local, dev, 0,
                         DCO_IROUTE_METRIC);
    }
#endif /* if defined(TARGET_LINUX) || defined(TARGET_FREEBSD) */
}

void
dco_delete_iroutes(struct multi_context *m, struct multi_instance *mi)
{
#if defined(TARGET_LINUX) || defined(TARGET_FREEBSD)
    if (!dco_enabled(&m->top.options))
    {
        return;
    }
    ASSERT(TUNNEL_TYPE(mi->context.c1.tuntap) == DEV_TYPE_TUN);

    struct context *c = &mi->context;
    const char *dev = c->c1.tuntap->actual_name;

    if (mi->context.c2.push_ifconfig_defined)
    {
        for (const struct iroute *ir = c->options.iroutes;
             ir;
             ir = ir->next)
        {
            net_route_v4_del(&m->top.net_ctx, &ir->network, ir->netbits,
                             &mi->context.c2.push_ifconfig_local, dev,
                             0, DCO_IROUTE_METRIC);
        }
    }

    if (mi->context.c2.push_ifconfig_ipv6_defined)
    {
        for (const struct iroute_ipv6 *ir6 = c->options.iroutes_ipv6;
             ir6;
             ir6 = ir6->next)
        {
            net_route_v6_del(&m->top.net_ctx, &ir6->network, ir6->netbits,
                             &mi->context.c2.push_ifconfig_ipv6_local, dev,
                             0, DCO_IROUTE_METRIC);
        }
    }
#endif /* if defined(TARGET_LINUX) || defined(TARGET_FREEBSD) */
}

#endif /* defined(ENABLE_DCO) */
