/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

#ifndef ENABLE_SMALL

#include "syshead.h"

#include "options_show.h"

#include "crypto.h"
#include "error.h"
#include "options.h"

static const char *
pull_filter_type_name(int type)
{
    if (type == PUF_TYPE_ACCEPT)
    {
        return "accept";
    }
    if (type == PUF_TYPE_IGNORE)
    {
        return "ignore";
    }
    if (type == PUF_TYPE_REJECT)
    {
        return "reject";
    }
    else
    {
        return "???";
    }
}

#define SHOW_PARM(name, value, format) msg(D_SHOW_PARMS, "  " #name " = " format, (value))
#define SHOW_STR(var)                  SHOW_PARM(var, (o->var ? o->var : "[UNDEF]"), "'%s'")
#define SHOW_STR_INLINE(var) \
    SHOW_PARM(var, o->var##_inline ? "[INLINE]" : (o->var ? o->var : "[UNDEF]"), "'%s'")
#define SHOW_INT(var)      SHOW_PARM(var, o->var, "%d")
#define SHOW_UINT(var)     SHOW_PARM(var, o->var, "%u")
#define SHOW_INT64(var)    SHOW_PARM(var, o->var, "%" PRIi64)
#define SHOW_UNSIGNED(var) SHOW_PARM(var, o->var, "0x%08x")
#define SHOW_BOOL(var)     SHOW_PARM(var, (o->var ? "ENABLED" : "DISABLED"), "%s");

#ifdef _WIN32

static void
show_dhcp_option_list(const char *name, const char *const *array, unsigned int len)
{
    for (unsigned int i = 0; i < len; ++i)
    {
        msg(D_SHOW_PARMS, "  %s[%u] = %s", name, i, array[i]);
    }
}

static void
show_dhcp_option_addrs(const char *name, const in_addr_t *array, unsigned int len)
{
    struct gc_arena gc = gc_new();
    for (unsigned int i = 0; i < len; ++i)
    {
        msg(D_SHOW_PARMS, "  %s[%u] = %s", name, i, print_in_addr_t(array[i], 0, &gc));
    }
    gc_free(&gc);
}

static void
show_tuntap_options(const struct tuntap_options *o)
{
    SHOW_BOOL(ip_win32_defined);
    SHOW_INT(ip_win32_type);
    SHOW_INT(dhcp_masq_offset);
    SHOW_INT(dhcp_lease_time);
    SHOW_INT(tap_sleep);
    SHOW_UNSIGNED(dhcp_options);
    SHOW_BOOL(dhcp_renew);
    SHOW_BOOL(dhcp_pre_release);
    SHOW_STR(domain);
    SHOW_STR(netbios_scope);
    SHOW_UNSIGNED(netbios_node_type);
    SHOW_BOOL(disable_nbt);

    show_dhcp_option_addrs("DNS", o->dns, o->dns_len);
    show_dhcp_option_addrs("WINS", o->wins, o->wins_len);
    show_dhcp_option_addrs("NTP", o->ntp, o->ntp_len);
    show_dhcp_option_addrs("NBDD", o->nbdd, o->nbdd_len);
    show_dhcp_option_list("DOMAIN-SEARCH", o->domain_search_list, o->domain_search_list_len);
}
#endif /* ifdef _WIN32 */

static const char *
print_vlan_accept(enum vlan_acceptable_frames mode)
{
    switch (mode)
    {
        case VLAN_ONLY_TAGGED:
            return "tagged";

        case VLAN_ONLY_UNTAGGED_OR_PRIORITY:
            return "untagged";

        case VLAN_ALL:
            return "all";
    }
    return NULL;
}

static void
show_p2mp_parms(const struct options *o)
{
    struct gc_arena gc = gc_new();

    msg(D_SHOW_PARMS, "  server_network = %s", print_in_addr_t(o->server_network, 0, &gc));
    msg(D_SHOW_PARMS, "  server_netmask = %s", print_in_addr_t(o->server_netmask, 0, &gc));
    msg(D_SHOW_PARMS, "  server_network_ipv6 = %s", print_in6_addr(o->server_network_ipv6, 0, &gc));
    SHOW_INT(server_netbits_ipv6);
    msg(D_SHOW_PARMS, "  server_bridge_ip = %s", print_in_addr_t(o->server_bridge_ip, 0, &gc));
    msg(D_SHOW_PARMS, "  server_bridge_netmask = %s",
        print_in_addr_t(o->server_bridge_netmask, 0, &gc));
    msg(D_SHOW_PARMS, "  server_bridge_pool_start = %s",
        print_in_addr_t(o->server_bridge_pool_start, 0, &gc));
    msg(D_SHOW_PARMS, "  server_bridge_pool_end = %s",
        print_in_addr_t(o->server_bridge_pool_end, 0, &gc));
    if (o->push_list.head)
    {
        const struct push_entry *e = o->push_list.head;
        while (e)
        {
            if (e->enable)
            {
                msg(D_SHOW_PARMS, "  push_entry = '%s'", e->option);
            }
            e = e->next;
        }
    }
    SHOW_BOOL(ifconfig_pool_defined);
    msg(D_SHOW_PARMS, "  ifconfig_pool_start = %s",
        print_in_addr_t(o->ifconfig_pool_start, 0, &gc));
    msg(D_SHOW_PARMS, "  ifconfig_pool_end = %s", print_in_addr_t(o->ifconfig_pool_end, 0, &gc));
    msg(D_SHOW_PARMS, "  ifconfig_pool_netmask = %s",
        print_in_addr_t(o->ifconfig_pool_netmask, 0, &gc));
    SHOW_STR(ifconfig_pool_persist_filename);
    SHOW_INT(ifconfig_pool_persist_refresh_freq);
    SHOW_BOOL(ifconfig_ipv6_pool_defined);
    msg(D_SHOW_PARMS, "  ifconfig_ipv6_pool_base = %s",
        print_in6_addr(o->ifconfig_ipv6_pool_base, 0, &gc));
    SHOW_INT(ifconfig_ipv6_pool_netbits);
    SHOW_INT(n_bcast_buf);
    SHOW_INT(tcp_queue_limit);
    SHOW_INT(real_hash_size);
    SHOW_INT(virtual_hash_size);
    SHOW_STR(client_connect_script);
    SHOW_STR(learn_address_script);
    SHOW_STR(client_disconnect_script);
    SHOW_STR(client_crresponse_script);
    SHOW_STR(client_config_dir);
    SHOW_BOOL(ccd_exclusive);
    SHOW_STR(tmp_dir);
    SHOW_BOOL(push_ifconfig_defined);
    msg(D_SHOW_PARMS, "  push_ifconfig_local = %s",
        print_in_addr_t(o->push_ifconfig_local, 0, &gc));
    msg(D_SHOW_PARMS, "  push_ifconfig_remote_netmask = %s",
        print_in_addr_t(o->push_ifconfig_remote_netmask, 0, &gc));
    SHOW_BOOL(push_ifconfig_ipv6_defined);
    msg(D_SHOW_PARMS, "  push_ifconfig_ipv6_local = %s/%d",
        print_in6_addr(o->push_ifconfig_ipv6_local, 0, &gc), o->push_ifconfig_ipv6_netbits);
    msg(D_SHOW_PARMS, "  push_ifconfig_ipv6_remote = %s",
        print_in6_addr(o->push_ifconfig_ipv6_remote, 0, &gc));
    SHOW_BOOL(enable_c2c);
    SHOW_BOOL(duplicate_cn);
    SHOW_INT(cf_max);
    SHOW_INT(cf_per);
    SHOW_INT(cf_initial_max);
    SHOW_INT(cf_initial_per);
    SHOW_UINT(max_clients);
    SHOW_INT(max_routes_per_client);
    SHOW_STR(auth_user_pass_verify_script);
    SHOW_BOOL(auth_user_pass_verify_script_via_file);
    SHOW_BOOL(auth_token_generate);
    SHOW_BOOL(force_key_material_export);
    SHOW_INT(auth_token_lifetime);
    SHOW_STR_INLINE(auth_token_secret_file);
#if PORT_SHARE
    SHOW_STR(port_share_host);
    SHOW_STR(port_share_port);
#endif
    SHOW_BOOL(vlan_tagging);
    msg(D_SHOW_PARMS, "  vlan_accept = %s", print_vlan_accept(o->vlan_accept));
    SHOW_INT(vlan_pvid);

    SHOW_BOOL(client);
    SHOW_BOOL(pull);
    SHOW_STR_INLINE(auth_user_pass_file);

    gc_free(&gc);
}

static void
show_http_proxy_options(const struct http_proxy_options *o)
{
    int i;
    msg(D_SHOW_PARMS, "BEGIN http_proxy");
    SHOW_STR(server);
    SHOW_STR(port);
    SHOW_STR(auth_method_string);
    SHOW_STR(auth_file);
    SHOW_STR(auth_file_up);
    SHOW_BOOL(inline_creds);
    SHOW_BOOL(nocache);
    SHOW_STR(http_version);
    SHOW_STR(user_agent);
    for (i = 0; i < MAX_CUSTOM_HTTP_HEADER && o->custom_headers[i].name; i++)
    {
        if (o->custom_headers[i].content)
        {
            msg(D_SHOW_PARMS, "  custom_header[%d] = %s: %s", i, o->custom_headers[i].name,
                o->custom_headers[i].content);
        }
        else
        {
            msg(D_SHOW_PARMS, "  custom_header[%d] = %s", i, o->custom_headers[i].name);
        }
    }
    msg(D_SHOW_PARMS, "END http_proxy");
}

static void
show_connection_entry(const struct connection_entry *o)
{
    /* Display the global proto only in client mode or with no '--local'*/
    if (o->local_list->len == 1)
    {
        msg(D_SHOW_PARMS, "  proto = %s", proto2ascii(o->proto, o->af, false));
    }

    msg(D_SHOW_PARMS, "  Local Sockets:");
    for (int i = 0; i < o->local_list->len; i++)
    {
        msg(D_SHOW_PARMS, "    [%s]:%s-%s", o->local_list->array[i]->local,
            o->local_list->array[i]->port,
            proto2ascii(o->local_list->array[i]->proto, o->af, false));
    }
    SHOW_STR(remote);
    SHOW_STR(remote_port);
    SHOW_BOOL(remote_float);
    SHOW_BOOL(bind_defined);
    SHOW_BOOL(bind_local);
    SHOW_BOOL(bind_ipv6_only);
    SHOW_INT(connect_retry_seconds);
    SHOW_INT(connect_timeout);

    if (o->http_proxy_options)
    {
        show_http_proxy_options(o->http_proxy_options);
    }
    SHOW_STR(socks_proxy_server);
    SHOW_STR(socks_proxy_port);
    SHOW_INT(tun_mtu);
    SHOW_BOOL(tun_mtu_defined);
    SHOW_INT(link_mtu);
    SHOW_BOOL(link_mtu_defined);
    SHOW_INT(tun_mtu_extra);
    SHOW_BOOL(tun_mtu_extra_defined);
    SHOW_INT(tls_mtu);

    SHOW_INT(mtu_discover_type);

#ifdef ENABLE_FRAGMENT
    SHOW_INT(fragment);
#endif
    SHOW_INT(mssfix);
    SHOW_BOOL(mssfix_encap);
    SHOW_BOOL(mssfix_fixed);

    SHOW_INT(explicit_exit_notification);

    SHOW_STR_INLINE(tls_auth_file);
    SHOW_PARM(key_direction, keydirection2ascii(o->key_direction, false, true), "%s");
    SHOW_STR_INLINE(tls_crypt_file);
    SHOW_STR_INLINE(tls_crypt_v2_file);
}


static void
show_connection_entries(const struct options *o)
{
    if (o->connection_list)
    {
        const struct connection_list *l = o->connection_list;
        int i;
        for (i = 0; i < l->len; ++i)
        {
            msg(D_SHOW_PARMS, "Connection profiles [%d]:", i);
            show_connection_entry(l->array[i]);
        }
    }
    else
    {
        msg(D_SHOW_PARMS, "Connection profiles [default]:");
        show_connection_entry(&o->ce);
    }
    msg(D_SHOW_PARMS, "Connection profiles END");
}

static void
show_pull_filter_list(const struct pull_filter_list *l)
{
    struct pull_filter *f;
    if (!l)
    {
        return;
    }

    msg(D_SHOW_PARMS, "  Pull filters:");
    for (f = l->head; f; f = f->next)
    {
        msg(D_SHOW_PARMS, "    %s \"%s\"", pull_filter_type_name(f->type), f->pattern);
    }
}

void
show_settings(const struct options *o)
{
    msg(D_SHOW_PARMS, "Current Parameter Settings:");

    SHOW_STR(config);

    SHOW_INT(mode);

#ifdef ENABLE_FEATURE_TUN_PERSIST
    SHOW_BOOL(persist_config);
    SHOW_INT(persist_mode);
#endif

    SHOW_BOOL(show_ciphers);
    SHOW_BOOL(show_digests);
    SHOW_BOOL(show_engines);
    SHOW_BOOL(genkey);
    SHOW_STR(genkey_filename);
    SHOW_STR(key_pass_file);
    SHOW_BOOL(show_tls_ciphers);

    SHOW_INT(connect_retry_max);
    show_connection_entries(o);

    SHOW_BOOL(remote_random);

    SHOW_STR(ipchange);
    SHOW_STR(dev);
    SHOW_STR(dev_type);
    SHOW_STR(dev_node);
#if defined(ENABLE_DCO)
    SHOW_BOOL(disable_dco);
#endif
    SHOW_STR(lladdr);
    SHOW_INT(topology);
    SHOW_STR(ifconfig_local);
    SHOW_STR(ifconfig_remote_netmask);
    SHOW_BOOL(ifconfig_noexec);
    SHOW_BOOL(ifconfig_nowarn);
    SHOW_STR(ifconfig_ipv6_local);
    SHOW_INT(ifconfig_ipv6_netbits);
    SHOW_STR(ifconfig_ipv6_remote);

    SHOW_INT(shaper);
    SHOW_INT(mtu_test);

    SHOW_BOOL(mlock);

    SHOW_INT(keepalive_ping);
    SHOW_INT(keepalive_timeout);
    SHOW_INT(inactivity_timeout);
    SHOW_INT(session_timeout);
    SHOW_INT64(inactivity_minimum_bytes);
    SHOW_INT(ping_send_timeout);
    SHOW_INT(ping_rec_timeout);
    SHOW_INT(ping_rec_timeout_action);
    SHOW_BOOL(ping_timer_remote);
    SHOW_INT(remap_sigusr1);
    SHOW_BOOL(persist_tun);
    SHOW_BOOL(persist_local_ip);
    SHOW_BOOL(persist_remote_ip);

#if PASSTOS_CAPABILITY
    SHOW_BOOL(passtos);
#endif

    SHOW_INT(resolve_retry_seconds);
    SHOW_BOOL(resolve_in_advance);

    SHOW_STR(username);
    SHOW_STR(groupname);
    SHOW_STR(chroot_dir);
    SHOW_STR(cd_dir);
#ifdef ENABLE_SELINUX
    SHOW_STR(selinux_context);
#endif
    SHOW_STR(writepid);
    SHOW_STR(up_script);
    SHOW_STR(down_script);
    SHOW_BOOL(down_pre);
    SHOW_BOOL(up_restart);
    SHOW_BOOL(up_delay);
    SHOW_BOOL(daemon);
    SHOW_BOOL(log);
    SHOW_BOOL(suppress_timestamps);
    SHOW_BOOL(machine_readable_output);
    SHOW_INT(nice);
    SHOW_INT(verbosity);
    SHOW_INT(mute);
#ifdef ENABLE_DEBUG
    SHOW_INT(gremlin);
#endif
    SHOW_STR(status_file);
    SHOW_INT(status_file_version);
    SHOW_INT(status_file_update_freq);

    SHOW_BOOL(occ);
    SHOW_INT(rcvbuf);
    SHOW_INT(sndbuf);
#if defined(TARGET_LINUX)
    SHOW_INT(mark);
#endif
    SHOW_INT(sockflags);

    SHOW_INT(comp.alg);
    SHOW_INT(comp.flags);

    SHOW_STR(route_script);
    SHOW_STR(route_default_gateway);
    SHOW_INT(route_default_metric);
    SHOW_INT(route_default_table_id);
    SHOW_BOOL(route_noexec);
    SHOW_INT(route_delay);
    SHOW_INT(route_delay_window);
    SHOW_BOOL(route_delay_defined);
    SHOW_BOOL(route_nopull);
    SHOW_BOOL(route_gateway_via_dhcp);
    SHOW_BOOL(allow_pull_fqdn);
    show_pull_filter_list(o->pull_filter_list);

    if (o->routes)
    {
        print_route_options(o->routes, D_SHOW_PARMS);
    }

    if (o->client_nat)
    {
        print_client_nat_list(o->client_nat, D_SHOW_PARMS);
    }

    show_dns_options(&o->dns_options);

#ifdef ENABLE_MANAGEMENT
    SHOW_STR(management_addr);
    SHOW_STR(management_port);
    SHOW_STR(management_user_pass);
    SHOW_INT(management_log_history_cache);
    SHOW_INT(management_echo_buffer_size);
    SHOW_STR(management_client_user);
    SHOW_STR(management_client_group);
    SHOW_INT(management_flags);
#endif
#ifdef ENABLE_PLUGIN
    if (o->plugin_list)
    {
        plugin_option_list_print(o->plugin_list, D_SHOW_PARMS);
    }
#endif

    SHOW_STR_INLINE(shared_secret_file);
    SHOW_PARM(key_direction, keydirection2ascii(o->key_direction, false, true), "%s");
    SHOW_STR(ciphername);
    SHOW_STR(ncp_ciphers);
    SHOW_STR(authname);
#ifndef ENABLE_CRYPTO_MBEDTLS
    SHOW_BOOL(engine);
#endif /* ENABLE_CRYPTO_MBEDTLS */
    SHOW_BOOL(mute_replay_warnings);
    SHOW_INT(replay_window);
    SHOW_INT(replay_time);
    SHOW_STR(packet_id_file);
    SHOW_BOOL(test_crypto);

    SHOW_BOOL(tls_server);
    SHOW_BOOL(tls_client);
    SHOW_STR_INLINE(ca_file);
    SHOW_STR(ca_path);
    SHOW_STR_INLINE(dh_file);
    if ((o->management_flags & MF_EXTERNAL_CERT))
    {
        SHOW_PARM("cert_file", "EXTERNAL_CERT", "%s");
    }
    else
    {
        SHOW_STR_INLINE(cert_file);
    }
    SHOW_STR_INLINE(extra_certs_file);

    if ((o->management_flags & MF_EXTERNAL_KEY))
    {
        SHOW_PARM("priv_key_file", "EXTERNAL_PRIVATE_KEY", "%s");
    }
    else
    {
        SHOW_STR_INLINE(priv_key_file);
    }
#ifndef ENABLE_CRYPTO_MBEDTLS
    SHOW_STR_INLINE(pkcs12_file);
#endif
#ifdef ENABLE_CRYPTOAPI
    SHOW_STR(cryptoapi_cert);
#endif
    SHOW_STR(cipher_list);
    SHOW_STR(cipher_list_tls13);
    SHOW_STR(tls_cert_profile);
    SHOW_STR(tls_verify);
    SHOW_STR(tls_export_peer_cert_dir);
    SHOW_INT(verify_x509_type);
    SHOW_STR(verify_x509_name);
    SHOW_STR_INLINE(crl_file);
    SHOW_INT(ns_cert_type);
    {
        int i;
        for (i = 0; i < MAX_PARMS; i++)
        {
            SHOW_INT(remote_cert_ku[i]);
        }
    }
    SHOW_STR(remote_cert_eku);
    if (o->verify_hash)
    {
        SHOW_INT(verify_hash_algo);
        SHOW_INT(verify_hash_depth);
        struct gc_arena gc = gc_new();
        const struct verify_hash_list *hl = o->verify_hash;
        int digest_len =
            (o->verify_hash_algo == MD_SHA1) ? SHA_DIGEST_LENGTH : SHA256_DIGEST_LENGTH;
        while (hl)
        {
            char *s = format_hex_ex(hl->hash, digest_len, 0, 1, ":", &gc);
            SHOW_PARM(verify_hash, s, "%s");
            hl = hl->next;
        }
        gc_free(&gc);
    }
    SHOW_INT(ssl_flags);

    SHOW_INT(tls_timeout);

    SHOW_INT64(renegotiate_bytes);
    SHOW_INT64(renegotiate_packets);
    SHOW_INT(renegotiate_seconds);

    SHOW_INT(handshake_window);
    SHOW_INT(transition_window);

    SHOW_BOOL(single_session);
    SHOW_BOOL(push_peer_info);
    SHOW_BOOL(tls_exit);

    SHOW_STR(tls_crypt_v2_metadata);

#ifdef ENABLE_PKCS11
    {
        int i;
        for (i = 0; i < MAX_PARMS && o->pkcs11_providers[i] != NULL; i++)
        {
            SHOW_PARM(pkcs11_providers, o->pkcs11_providers[i], "%s");
        }
    }
    {
        int i;
        for (i = 0; i < MAX_PARMS; i++)
        {
            SHOW_PARM(pkcs11_protected_authentication,
                      o->pkcs11_protected_authentication[i] ? "ENABLED" : "DISABLED", "%s");
        }
    }
    {
        int i;
        for (i = 0; i < MAX_PARMS; i++)
        {
            SHOW_PARM(pkcs11_private_mode, o->pkcs11_private_mode[i], "%08x");
        }
    }
    {
        int i;
        for (i = 0; i < MAX_PARMS; i++)
        {
            SHOW_PARM(pkcs11_cert_private, o->pkcs11_cert_private[i] ? "ENABLED" : "DISABLED",
                      "%s");
        }
    }
    SHOW_INT(pkcs11_pin_cache_period);
    SHOW_STR(pkcs11_id);
    SHOW_BOOL(pkcs11_id_management);
#endif /* ENABLE_PKCS11 */

    show_p2mp_parms(o);

#ifdef _WIN32
    SHOW_BOOL(show_net_up);
    SHOW_INT(route_method);
    SHOW_BOOL(block_outside_dns);
    show_tuntap_options(&o->tuntap_options);
#endif
}

#endif /* ifndef ENABLE_SMALL */
