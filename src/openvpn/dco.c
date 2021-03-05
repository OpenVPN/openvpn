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
#include "errlevel.h"
#include "networking.h"
#include "multi.h"
#include "ssl_verify.h"
#include "ssl_ncp.h"
#include "dco.h"

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

    switch(actual->dest.addr.sa.sa_family)
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
#else
    return false;
#endif
}

int
dco_multi_add_new_peer(struct multi_context *m, struct multi_instance *mi)
{
    struct context *c = &mi->context;

    int peer_id = mi->context.c2.tls_multi->peer_id;
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

    struct in_addr remote_ip4 = { 0 };
    struct in6_addr *remote_addr6 = NULL;
    struct in_addr *remote_addr4 = NULL;

    /* In server mode we need to fetch the remote addresses from the push config */
    if (c->c2.push_ifconfig_defined)
    {
        remote_ip4.s_addr =  htonl(c->c2.push_ifconfig_local);
        remote_addr4 = &remote_ip4;
    }
    if (c->c2.push_ifconfig_ipv6_defined)
    {
        remote_addr6 = &c->c2.push_ifconfig_ipv6_local;
    }

    if (dco_multi_get_localaddr(m, mi, &local))
    {
        localaddr = (struct sockaddr *)&local;
    }

    int ret = dco_new_peer(&c->c1.tuntap->dco, peer_id, sd, localaddr,
                           remoteaddr, remote_addr4, remote_addr6);
    if (ret < 0)
    {
        return ret;
    }

    c->c2.tls_multi->dco_peer_added = true;

    if (c->mode == CM_CHILD_TCP)
    {
        multi_tcp_dereference_instance(m->mtcp, mi);
        if (close(sd))
        {
            msg(D_DCO|M_ERRNO, "error closing TCP socket after DCO handover");
        }
        c->c2.link_socket->info.dco_installed = true;
        c->c2.link_socket->sd = SOCKET_UNDEFINED;
    }

    return 0;
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

    if (dco_enabled(&c->options) && !c->c2.link_socket->info.dco_installed)
    {
        ASSERT(ls->info.connection_established);

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
    }

    return 0;
}

void dco_remove_peer(struct context *c)
{
    if (!dco_enabled(&c->options))
    {
        return;
    }
    if (c->c1.tuntap && c->c2.tls_multi && c->c2.tls_multi->dco_peer_added)
    {
        c->c2.tls_multi->dco_peer_added = false;
        dco_del_peer(&c->c1.tuntap->dco, c->c2.tls_multi->peer_id);
    }
}

/**
 * Find a usable key that is not the primary (i.e. the secondary key)
 *
 * @param multi     The TLS struct to retrieve keys from
 * @param primary   The primary key that should be skipped doring the scan
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
    ASSERT(!primary || primary->dco_status != DCO_NOT_INSTALLED);

    /* no primary key available -> no usable key exists, therefore we should
     * tell DCO to simply wipe all keys
     */
    if (!primary)
    {
        msg(D_DCO, "No encryption key found. Purging data channel keys");

        dco_del_key(dco, multi->peer_id, OVPN_KEY_SLOT_PRIMARY);
        dco_del_key(dco, multi->peer_id, OVPN_KEY_SLOT_SECONDARY);
        multi->dco_keys_installed = 0;
        return;
    }

    struct key_state *secondary = dco_get_secondary_key(multi, primary);
    ASSERT(!secondary || secondary->dco_status != DCO_NOT_INSTALLED);

    /* the current primary key was installed as secondary in DCO, this means
     * that userspace has promoted it and we should tell DCO to swap keys
     */
    if (primary->dco_status == DCO_INSTALLED_SECONDARY)
    {
        msg(D_DCO_DEBUG, "Swapping primary and secondary keys, now: id1=%d id2=%d",
            primary->key_id, secondary ? secondary->key_id : -1);

        dco_swap_keys(dco, multi->peer_id);
        primary->dco_status = DCO_INSTALLED_PRIMARY;
        if (secondary)
        {
            secondary->dco_status = DCO_INSTALLED_SECONDARY;
        }
    }

    /* if we have no secondary key anymore, inform DCO about it */
    if (!secondary && multi->dco_keys_installed == 2)
    {
        dco_del_key(dco, multi->peer_id, OVPN_KEY_SLOT_SECONDARY);
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
        switch (slot)
        {
            case OVPN_KEY_SLOT_PRIMARY:
                ks->dco_status = DCO_INSTALLED_PRIMARY;
                break;
            case OVPN_KEY_SLOT_SECONDARY:
                ks->dco_status = DCO_INSTALLED_SECONDARY;
                break;
            default:
                ASSERT(false);
        }
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

static bool
dco_check_option_conflict_ce(const struct connection_entry *ce, int msglevel)
{
    if (ce->fragment)
    {
        msg(msglevel, "Note: --fragment disables data channel offload.");
        return true;
    }

    if (ce->http_proxy_options)
    {
        msg(msglevel, "Note: --http-proxy disables data channel offload.");
        return true;
    }

    if (ce->socks_proxy_server)
    {
        msg(msglevel, "Note --socks-proxy disable data channel offload.");
        return true;
    }

    return false;
}

static bool
dco_check_option_conflict_platform(int msglevel, const struct options *o)
{
#if defined(_WIN32)
    if (o->mode == MODE_SERVER)
    {
        msg(msglevel, "Only client and p2p data channel offload is supported "
                      "with ovpn-dco-win.");
        return true;
    }
    if (o->persist_tun)
    {
        msg(msglevel, "--persist-tun is not supported with ovpn-dco-win.");
        return true;
    }
#endif
    return false;
}

bool
dco_check_option_conflict(int msglevel, const struct options *o)
{
    if (o->tuntap_options.disable_dco)
    {
        /* already disabled by --disable-dco, no need to print warnings */
        return true;
    }

    if (!dco_available(msglevel))
    {
        return true;
    }

    if (dco_check_option_conflict_platform(msglevel, o))
    {
        return true;
    }

    if (dev_type_enum(o->dev, o->dev_type) != DEV_TYPE_TUN)
    {
        msg(msglevel, "Note: dev-type not tun, disabling data channel offload.");
        return true;
    }

    /* At this point the ciphers have already been normalised */
    if (o->enable_ncp_fallback
        && !tls_item_in_cipher_list(o->ciphername, dco_get_supported_ciphers()))
    {
        msg(msglevel, "Note: --data-cipher-fallback with cipher '%s' "
                      "disables data channel offload.", o->ciphername);
        return true;
    }

    if (o->connection_list)
    {
        const struct connection_list *l = o->connection_list;
        for (int i = 0; i < l->len; ++i)
        {
            if (dco_check_option_conflict_ce(l->array[i], msglevel))
            {
                return true;
            }
        }
    }
    else
    {
        if (dco_check_option_conflict_ce(&o->ce, msglevel))
        {
            return true;
        }
    }

    if (o->mode == MODE_SERVER && o->topology != TOP_SUBNET)
    {
        msg(msglevel, "Note: NOT using '--topology subnet' disables data channel offload.");
        return true;
    }

#ifdef USE_COMP
    if(o->comp.alg != COMP_ALG_UNDEF)
    {
        msg(msglevel, "Note: Using compression disables data channel offload.");

        if (o->mode == MODE_SERVER && !(o->comp.flags & COMP_F_MIGRATE))
        {
            /* We can end up here from the multi.c call, only print the
             * note if it is not already enabled */
            msg(msglevel, "Consider using the '--compress migrate' option.");
        }
        return true;
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
            return true;
        }
    }
    gc_free(&gc);

    return false;
}

/* These methods are currently Linux specific but likely to be used any
 * platform that implements Server side DCO
 */

void
dco_install_iroute(struct multi_context *m, struct multi_instance *mi,
                   struct mroute_addr *addr)
{
#if defined(TARGET_LINUX)
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
        int netbits = 128;
        if (addr->type & MR_WITH_NETBITS)
        {
            netbits = addr->netbits;
        }

        net_route_v6_add(&m->top.net_ctx, &addr->v6.addr, netbits,
                         &mi->context.c2.push_ifconfig_ipv6_local, dev, 0,
                         DCO_IROUTE_METRIC);
    }
    else if (addrtype == MR_ADDR_IPV4)
    {
        int netbits = 32;
        if (addr->type & MR_WITH_NETBITS)
        {
            netbits = addr->netbits;
        }

        in_addr_t dest = htonl(addr->v4.addr);
        net_route_v4_add(&m->top.net_ctx, &dest, netbits,
                         &mi->context.c2.push_ifconfig_local, dev, 0,
                         DCO_IROUTE_METRIC);
    }
#endif
}

void
dco_delete_iroutes(struct multi_context *m, struct multi_instance *mi)
{
#if defined(TARGET_LINUX)
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
#endif
}

#endif /* defined(ENABLE_DCO) */
