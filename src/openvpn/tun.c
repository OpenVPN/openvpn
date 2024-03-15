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

/*
 * Support routines for configuring and accessing TUN/TAP
 * virtual network adapters.
 *
 * This file is based on the TUN/TAP driver interface routines
 * from VTun by Maxim Krasnyansky <max_mk@yahoo.com>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "openvpn.h"
#include "tun.h"
#include "fdmisc.h"
#include "common.h"
#include "run_command.h"
#include "socket.h"
#include "manage.h"
#include "route.h"
#include "win32.h"
#include "block_dns.h"
#include "networking.h"

#include "memdbg.h"

#ifdef _WIN32
#include "openvpn-msg.h"
#endif

#include <string.h>

#ifdef _WIN32

const static GUID GUID_DEVCLASS_NET = { 0x4d36e972L, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };
const static GUID GUID_DEVINTERFACE_NET = { 0xcac88484, 0x7515, 0x4c03, { 0x82, 0xe6, 0x71, 0xa8, 0x7a, 0xba, 0xc3, 0x61 } };

/* #define SIMULATE_DHCP_FAILED */       /* simulate bad DHCP negotiation */

#define NI_TEST_FIRST  (1<<0)
#define NI_IP_NETMASK  (1<<1)
#define NI_OPTIONS     (1<<2)

static void netsh_ifconfig(const struct tuntap_options *to,
                           DWORD adapter_index,
                           const in_addr_t ip,
                           const in_addr_t netmask,
                           const unsigned int flags);

static void windows_set_mtu(const int iface_index,
                            const short family,
                            const int mtu);

static void netsh_set_dns6_servers(const struct in6_addr *addr_list,
                                   const int addr_len,
                                   DWORD adapter_index);

static void netsh_command(const struct argv *a, int n, int msglevel);

static void exec_command(const char *prefix, const struct argv *a, int n, int msglevel);

static const char *netsh_get_id(const char *dev_node, struct gc_arena *gc);

static bool
do_address_service(const bool add, const short family, const struct tuntap *tt)
{
    bool ret = false;
    ack_message_t ack;
    struct gc_arena gc = gc_new();
    HANDLE pipe = tt->options.msg_channel;

    address_message_t addr = {
        .header = {
            (add ? msg_add_address : msg_del_address),
            sizeof(address_message_t),
            0
        },
        .family = family,
        .iface = { .index = tt->adapter_index, .name = "" }
    };

    if (addr.iface.index == TUN_ADAPTER_INDEX_INVALID)
    {
        strncpy(addr.iface.name, tt->actual_name, sizeof(addr.iface.name));
        addr.iface.name[sizeof(addr.iface.name) - 1] = '\0';
    }

    if (addr.family == AF_INET)
    {
        addr.address.ipv4.s_addr = htonl(tt->local);
        addr.prefix_len = netmask_to_netbits2(tt->adapter_netmask);
        msg(D_IFCONFIG, "INET address service: %s %s/%d",
            add ? "add" : "remove",
            print_in_addr_t(tt->local, 0, &gc), addr.prefix_len);
    }
    else
    {
        addr.address.ipv6 = tt->local_ipv6;
        addr.prefix_len = (tt->type == DEV_TYPE_TUN) ? 128 : tt->netbits_ipv6;
        msg(D_IFCONFIG, "INET6 address service: %s %s/%d",
            add ? "add" : "remove",
            print_in6_addr(tt->local_ipv6, 0, &gc), addr.prefix_len);
    }

    if (!send_msg_iservice(pipe, &addr, sizeof(addr), &ack, "TUN"))
    {
        goto out;
    }

    if (ack.error_number != NO_ERROR)
    {
        msg(M_WARN, "TUN: %s address failed using service: %s [status=%u if_index=%d]",
            (add ? "adding" : "deleting"), strerror_win32(ack.error_number, &gc),
            ack.error_number, addr.iface.index);
        goto out;
    }

    ret = true;

out:
    gc_free(&gc);
    return ret;
}

static void
do_dns_domain_service(bool add, const struct tuntap *tt)
{
    ack_message_t ack;
    struct gc_arena gc = gc_new();
    HANDLE pipe = tt->options.msg_channel;

    if (!tt->options.domain) /* no  domain to add or delete */
    {
        goto out;
    }

    /* Use dns_cfg_msg with addr_len = 0 for setting only the DOMAIN */
    dns_cfg_message_t dns = {
        .header = {
            (add ? msg_add_dns_cfg : msg_del_dns_cfg),
            sizeof(dns_cfg_message_t),
            0
        },
        .iface = { .index = tt->adapter_index, .name = "" },
        .domains = "",      /* set below */
        .family = AF_INET,  /* unused */
        .addr_len = 0       /* add/delete only the domain, not DNS servers */
    };

    strncpynt(dns.iface.name, tt->actual_name, sizeof(dns.iface.name));
    strncpynt(dns.domains, tt->options.domain, sizeof(dns.domains));
    /* truncation of domain name is not checked as it can't happen
     * with 512 bytes room in dns.domains.
     */

    msg(D_LOW, "%s dns domain on '%s' (if_index = %d) using service",
        (add ? "Setting" : "Deleting"), dns.iface.name, dns.iface.index);
    if (!send_msg_iservice(pipe, &dns, sizeof(dns), &ack, "TUN"))
    {
        goto out;
    }

    if (ack.error_number != NO_ERROR)
    {
        msg(M_WARN, "TUN: %s dns domain failed using service: %s [status=%u if_name=%s]",
            (add ? "adding" : "deleting"), strerror_win32(ack.error_number, &gc),
            ack.error_number, dns.iface.name);
        goto out;
    }

    msg(M_INFO, "DNS domain %s using service", (add ? "set" : "deleted"));

out:
    gc_free(&gc);
}

static void
do_dns_service(bool add, const short family, const struct tuntap *tt)
{
    ack_message_t ack;
    struct gc_arena gc = gc_new();
    HANDLE pipe = tt->options.msg_channel;
    int len = family == AF_INET6 ? tt->options.dns6_len : tt->options.dns_len;
    int addr_len = add ? len : 0;
    const char *ip_proto_name = family == AF_INET6 ? "IPv6" : "IPv4";

    if (len == 0)
    {
        /* nothing to do */
        goto out;
    }

    /* Use dns_cfg_msg with domain = "" for setting only the DNS servers */
    dns_cfg_message_t dns = {
        .header = {
            (add ? msg_add_dns_cfg : msg_del_dns_cfg),
            sizeof(dns_cfg_message_t),
            0
        },
        .iface = { .index = tt->adapter_index, .name = "" },
        .domains = "",
        .family = family,
        .addr_len = addr_len
    };

    /* interface name is required */
    strncpy(dns.iface.name, tt->actual_name, sizeof(dns.iface.name));
    dns.iface.name[sizeof(dns.iface.name) - 1] = '\0';

    if (addr_len > _countof(dns.addr))
    {
        addr_len = _countof(dns.addr);
        dns.addr_len = addr_len;
        msg(M_WARN, "Number of %s DNS addresses sent to service truncated to %d",
            ip_proto_name, addr_len);
    }

    for (int i = 0; i < addr_len; ++i)
    {
        if (family == AF_INET6)
        {
            dns.addr[i].ipv6 = tt->options.dns6[i];
        }
        else
        {
            dns.addr[i].ipv4.s_addr = htonl(tt->options.dns[i]);
        }
    }

    msg(D_LOW, "%s %s dns servers on '%s' (if_index = %d) using service",
        (add ? "Setting" : "Deleting"), ip_proto_name, dns.iface.name, dns.iface.index);

    if (!send_msg_iservice(pipe, &dns, sizeof(dns), &ack, "TUN"))
    {
        goto out;
    }

    if (ack.error_number != NO_ERROR)
    {
        msg(M_WARN, "TUN: %s %s dns failed using service: %s [status=%u if_name=%s]",
            (add ? "adding" : "deleting"), ip_proto_name, strerror_win32(ack.error_number, &gc),
            ack.error_number, dns.iface.name);
        goto out;
    }

    msg(M_INFO, "%s dns servers %s using service", ip_proto_name, (add ? "set" : "deleted"));

out:
    gc_free(&gc);
}

static void
do_wins_service(bool add, const struct tuntap *tt)
{
    ack_message_t ack;
    struct gc_arena gc = gc_new();
    HANDLE pipe = tt->options.msg_channel;
    int addr_len = add ? tt->options.wins_len : 0;

    if (tt->options.wins_len == 0)
    {
        /* nothing to do */
        goto out;
    }

    wins_cfg_message_t wins = {
        .header = {
            (add ? msg_add_wins_cfg : msg_del_wins_cfg),
            sizeof(wins_cfg_message_t),
            0
        },
        .iface = {.index = tt->adapter_index, .name = "" },
        .addr_len = addr_len
    };

    /* interface name is required */
    strncpy(wins.iface.name, tt->actual_name, sizeof(wins.iface.name));
    wins.iface.name[sizeof(wins.iface.name) - 1] = '\0';

    if (addr_len > _countof(wins.addr))
    {
        addr_len = _countof(wins.addr);
        wins.addr_len = addr_len;
        msg(M_WARN, "Number of WINS addresses sent to service truncated to %d",
            addr_len);
    }

    for (int i = 0; i < addr_len; ++i)
    {
        wins.addr[i].ipv4.s_addr = htonl(tt->options.wins[i]);
    }

    msg(D_LOW, "%s WINS servers on '%s' (if_index = %d) using service",
        (add ? "Setting" : "Deleting"), wins.iface.name, wins.iface.index);

    if (!send_msg_iservice(pipe, &wins, sizeof(wins), &ack, "TUN"))
    {
        goto out;
    }

    if (ack.error_number != NO_ERROR)
    {
        msg(M_WARN, "TUN: %s WINS failed using service: %s [status=%u if_name=%s]",
            (add ? "adding" : "deleting"), strerror_win32(ack.error_number, &gc),
            ack.error_number, wins.iface.name);
        goto out;
    }

    msg(M_INFO, "WINS servers %s using service", (add ? "set" : "deleted"));

out:
    gc_free(&gc);
}

static bool
do_set_mtu_service(const struct tuntap *tt, const short family, const int mtu)
{
    bool ret = false;
    ack_message_t ack;
    struct gc_arena gc = gc_new();
    HANDLE pipe = tt->options.msg_channel;
    const char *family_name = (family == AF_INET6) ? "IPv6" : "IPv4";
    set_mtu_message_t mtu_msg = {
        .header = {
            msg_set_mtu,
            sizeof(set_mtu_message_t),
            0
        },
        .iface = {.index = tt->adapter_index},
        .mtu = mtu,
        .family = family
    };
    strncpynt(mtu_msg.iface.name, tt->actual_name, sizeof(mtu_msg.iface.name));
    if (family == AF_INET6 && mtu < 1280)
    {
        msg(M_INFO, "NOTE: IPv6 interface MTU < 1280 conflicts with IETF standards and might not work");
    }

    if (!send_msg_iservice(pipe, &mtu_msg, sizeof(mtu_msg), &ack, "Set_mtu"))
    {
        goto out;
    }

    if (ack.error_number != NO_ERROR)
    {
        msg(M_NONFATAL, "TUN: setting %s mtu using service failed: %s [status=%u if_index=%d]",
            family_name, strerror_win32(ack.error_number, &gc), ack.error_number, mtu_msg.iface.index);
    }
    else
    {
        msg(M_INFO, "%s MTU set to %d on interface %d using service", family_name, mtu, mtu_msg.iface.index);
        ret = true;
    }

out:
    gc_free(&gc);
    return ret;
}

static void
do_dns_domain_wmic(bool add, const struct tuntap *tt)
{
    if (!tt->options.domain)
    {
        return;
    }

    struct argv argv = argv_new();
    argv_printf(&argv, "%s%s nicconfig where (InterfaceIndex=%ld) call SetDNSDomain '%s'",
                get_win_sys_path(), WMIC_PATH_SUFFIX, tt->adapter_index, add ? tt->options.domain : "");
    exec_command("WMIC", &argv, 1, M_WARN);

    argv_free(&argv);
}

#endif /* ifdef _WIN32 */

#ifdef TARGET_SOLARIS
static void solaris_error_close(struct tuntap *tt, const struct env_set *es, const char *actual, bool unplumb_inet6);

#include <stropts.h>
#endif

#if defined(TARGET_DARWIN) && HAVE_NET_IF_UTUN_H
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <sys/sys_domain.h>
#endif

static void clear_tuntap(struct tuntap *tuntap);

bool
is_dev_type(const char *dev, const char *dev_type, const char *match_type)
{
    ASSERT(match_type);
    if (!dev)
    {
        return false;
    }
    if (dev_type)
    {
        return !strcmp(dev_type, match_type);
    }
    else
    {
        return !strncmp(dev, match_type, strlen(match_type));
    }
}

int
dev_type_enum(const char *dev, const char *dev_type)
{
    if (is_dev_type(dev, dev_type, "tun"))
    {
        return DEV_TYPE_TUN;
    }
    else if (is_dev_type(dev, dev_type, "tap"))
    {
        return DEV_TYPE_TAP;
    }
    else if (is_dev_type(dev, dev_type, "null"))
    {
        return DEV_TYPE_NULL;
    }
    else
    {
        return DEV_TYPE_UNDEF;
    }
}

const char *
dev_type_string(const char *dev, const char *dev_type)
{
    switch (dev_type_enum(dev, dev_type))
    {
        case DEV_TYPE_TUN:
            return "tun";

        case DEV_TYPE_TAP:
            return "tap";

        case DEV_TYPE_NULL:
            return "null";

        default:
            return "[unknown-dev-type]";
    }
}

/*
 * Try to predict the actual TUN/TAP device instance name,
 * before the device is actually opened.
 */
const char *
guess_tuntap_dev(const char *dev,
                 const char *dev_type,
                 const char *dev_node,
                 struct gc_arena *gc)
{
#ifdef _WIN32
    const int dt = dev_type_enum(dev, dev_type);
    if (dt == DEV_TYPE_TUN || dt == DEV_TYPE_TAP)
    {
        return netsh_get_id(dev_node, gc);
    }
#endif

    /* default case */
    return dev;
}


/* --ifconfig-nowarn disables some options sanity checking */
static const char ifconfig_warn_how_to_silence[] = "(silence this warning with --ifconfig-nowarn)";

/*
 * If !tun, make sure ifconfig_remote_netmask looks
 *  like a netmask.
 *
 * If tun, make sure ifconfig_remote_netmask looks
 *  like an IPv4 address.
 */
static void
ifconfig_sanity_check(bool tun, in_addr_t addr, int topology)
{
    struct gc_arena gc = gc_new();
    const bool looks_like_netmask = ((addr & 0xFF000000) == 0xFF000000);
    if (tun)
    {
        if (looks_like_netmask && (topology == TOP_NET30 || topology == TOP_P2P))
        {
            msg(M_WARN, "WARNING: Since you are using --dev tun with a point-to-point topology, the second argument to --ifconfig must be an IP address.  You are using something (%s) that looks more like a netmask. %s",
                print_in_addr_t(addr, 0, &gc),
                ifconfig_warn_how_to_silence);
        }
    }
    else /* tap */
    {
        if (!looks_like_netmask)
        {
            msg(M_WARN, "WARNING: Since you are using --dev tap, the second argument to --ifconfig must be a netmask, for example something like 255.255.255.0. %s",
                ifconfig_warn_how_to_silence);
        }
    }
    gc_free(&gc);
}

/*
 * Check that --local and --remote addresses do not
 * clash with ifconfig addresses or subnet.
 */
static void
check_addr_clash(const char *name,
                 int type,
                 in_addr_t public,
                 in_addr_t local,
                 in_addr_t remote_netmask)
{
    struct gc_arena gc = gc_new();
#if 0
    msg(M_INFO, "CHECK_ADDR_CLASH type=%d public=%s local=%s, remote_netmask=%s",
        type,
        print_in_addr_t(public, 0, &gc),
        print_in_addr_t(local, 0, &gc),
        print_in_addr_t(remote_netmask, 0, &gc));
#endif

    if (public)
    {
        if (type == DEV_TYPE_TUN)
        {
            const in_addr_t test_netmask = 0xFFFFFF00;
            const in_addr_t public_net = public &test_netmask;
            const in_addr_t local_net = local & test_netmask;
            const in_addr_t remote_net = remote_netmask & test_netmask;

            if (public == local || public == remote_netmask)
            {
                msg(M_WARN,
                    "WARNING: --%s address [%s] conflicts with --ifconfig address pair [%s, %s]. %s",
                    name,
                    print_in_addr_t(public, 0, &gc),
                    print_in_addr_t(local, 0, &gc),
                    print_in_addr_t(remote_netmask, 0, &gc),
                    ifconfig_warn_how_to_silence);
            }

            if (public_net == local_net || public_net == remote_net)
            {
                msg(M_WARN,
                    "WARNING: potential conflict between --%s address [%s] and --ifconfig address pair [%s, %s] -- this is a warning only that is triggered when local/remote addresses exist within the same /24 subnet as --ifconfig endpoints. %s",
                    name,
                    print_in_addr_t(public, 0, &gc),
                    print_in_addr_t(local, 0, &gc),
                    print_in_addr_t(remote_netmask, 0, &gc),
                    ifconfig_warn_how_to_silence);
            }
        }
        else if (type == DEV_TYPE_TAP)
        {
            const in_addr_t public_network = public &remote_netmask;
            const in_addr_t virtual_network = local & remote_netmask;
            if (public_network == virtual_network)
            {
                msg(M_WARN,
                    "WARNING: --%s address [%s] conflicts with --ifconfig subnet [%s, %s] -- local and remote addresses cannot be inside of the --ifconfig subnet. %s",
                    name,
                    print_in_addr_t(public, 0, &gc),
                    print_in_addr_t(local, 0, &gc),
                    print_in_addr_t(remote_netmask, 0, &gc),
                    ifconfig_warn_how_to_silence);
            }
        }
    }
    gc_free(&gc);
}

/*
 * Issue a warning if ip/netmask (on the virtual IP network) conflicts with
 * the settings on the local LAN.  This is designed to flag issues where
 * (for example) the OpenVPN server LAN is running on 192.168.1.x, but then
 * an OpenVPN client tries to connect from a public location that is also running
 * off of a router set to 192.168.1.x.
 */
void
check_subnet_conflict(const in_addr_t ip,
                      const in_addr_t netmask,
                      const char *prefix)
{
#if 0 /* too many false positives */
    struct gc_arena gc = gc_new();
    in_addr_t lan_gw = 0;
    in_addr_t lan_netmask = 0;

    if (get_default_gateway(&lan_gw, &lan_netmask) && lan_netmask)
    {
        const in_addr_t lan_network = lan_gw & lan_netmask;
        const in_addr_t network = ip & netmask;

        /* do the two subnets defined by network/netmask and lan_network/lan_netmask intersect? */
        if ((network & lan_netmask) == lan_network
            || (lan_network & netmask) == network)
        {
            msg(M_WARN, "WARNING: potential %s subnet conflict between local LAN [%s/%s] and remote VPN [%s/%s]",
                prefix,
                print_in_addr_t(lan_network, 0, &gc),
                print_in_addr_t(lan_netmask, 0, &gc),
                print_in_addr_t(network, 0, &gc),
                print_in_addr_t(netmask, 0, &gc));
        }
    }
    gc_free(&gc);
#endif /* if 0 */
}

void
warn_on_use_of_common_subnets(openvpn_net_ctx_t *ctx)
{
    struct gc_arena gc = gc_new();
    struct route_gateway_info rgi;
    const int needed = (RGI_ADDR_DEFINED|RGI_NETMASK_DEFINED);

    get_default_gateway(&rgi, ctx);
    if ((rgi.flags & needed) == needed)
    {
        const in_addr_t lan_network = rgi.gateway.addr & rgi.gateway.netmask;
        if (lan_network == 0xC0A80000 || lan_network == 0xC0A80100)
        {
            msg(M_WARN, "NOTE: your local LAN uses the extremely common subnet address 192.168.0.x or 192.168.1.x.  Be aware that this might create routing conflicts if you connect to the VPN server from public locations such as internet cafes that use the same subnet.");
        }
    }
    gc_free(&gc);
}

/*
 * Return a string to be used for options compatibility check
 * between peers.
 */
const char *
ifconfig_options_string(const struct tuntap *tt, bool remote, bool disable, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);
    if (tt->did_ifconfig_setup && !disable)
    {
        if (tt->type == DEV_TYPE_TAP || (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET))
        {
            buf_printf(&out, "%s %s",
                       print_in_addr_t(tt->local & tt->remote_netmask, 0, gc),
                       print_in_addr_t(tt->remote_netmask, 0, gc));
        }
        else if (tt->type == DEV_TYPE_TUN)
        {
            const char *l, *r;
            if (remote)
            {
                r = print_in_addr_t(tt->local, 0, gc);
                l = print_in_addr_t(tt->remote_netmask, 0, gc);
            }
            else
            {
                l = print_in_addr_t(tt->local, 0, gc);
                r = print_in_addr_t(tt->remote_netmask, 0, gc);
            }
            buf_printf(&out, "%s %s", r, l);
        }
        else
        {
            buf_printf(&out, "[undef]");
        }
    }
    return BSTR(&out);
}

/*
 * Return a status string describing wait state.
 */
const char *
tun_stat(const struct tuntap *tt, unsigned int rwflags, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(64, gc);
    if (tt)
    {
        if (rwflags & EVENT_READ)
        {
            buf_printf(&out, "T%s",
                       (tt->rwflags_debug & EVENT_READ) ? "R" : "r");
#ifdef _WIN32
            buf_printf(&out, "%s",
                       overlapped_io_state_ascii(&tt->reads));
#endif
        }
        if (rwflags & EVENT_WRITE)
        {
            buf_printf(&out, "T%s",
                       (tt->rwflags_debug & EVENT_WRITE) ? "W" : "w");
#ifdef _WIN32
            buf_printf(&out, "%s",
                       overlapped_io_state_ascii(&tt->writes));
#endif
        }
    }
    else
    {
        buf_printf(&out, "T?");
    }
    return BSTR(&out);
}

/*
 * Return true for point-to-point topology, false for subnet topology
 */
bool
is_tun_p2p(const struct tuntap *tt)
{
    bool tun = false;

    if (tt->type == DEV_TYPE_TAP
        || (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET)
        || tt->type == DEV_TYPE_NULL)
    {
        tun = false;
    }
    else if (tt->type == DEV_TYPE_TUN)
    {
        tun = true;
    }
    else
    {
        msg(M_FATAL, "Error: problem with tun vs. tap setting"); /* JYFIXME -- needs to be caught earlier, in init_tun? */

    }
    return tun;
}

/*
 * Set the ifconfig_* environment variables, both for IPv4 and IPv6
 */
void
do_ifconfig_setenv(const struct tuntap *tt, struct env_set *es)
{
    struct gc_arena gc = gc_new();
    const char *ifconfig_local = print_in_addr_t(tt->local, 0, &gc);
    const char *ifconfig_remote_netmask = print_in_addr_t(tt->remote_netmask, 0, &gc);

    /*
     * Set environmental variables with ifconfig parameters.
     */
    if (tt->did_ifconfig_setup)
    {
        bool tun = is_tun_p2p(tt);

        setenv_str(es, "ifconfig_local", ifconfig_local);
        if (tun)
        {
            setenv_str(es, "ifconfig_remote", ifconfig_remote_netmask);
        }
        else
        {
            setenv_str(es, "ifconfig_netmask", ifconfig_remote_netmask);
        }
    }

    if (tt->did_ifconfig_ipv6_setup)
    {
        const char *ifconfig_ipv6_local = print_in6_addr(tt->local_ipv6, 0, &gc);
        const char *ifconfig_ipv6_remote = print_in6_addr(tt->remote_ipv6, 0, &gc);

        setenv_str(es, "ifconfig_ipv6_local", ifconfig_ipv6_local);
        setenv_int(es, "ifconfig_ipv6_netbits", tt->netbits_ipv6);
        setenv_str(es, "ifconfig_ipv6_remote", ifconfig_ipv6_remote);
    }

    gc_free(&gc);
}

/*
 * Init tun/tap object.
 *
 * Set up tuntap structure for ifconfig,
 * but don't execute yet.
 */
struct tuntap *
init_tun(const char *dev,        /* --dev option */
         const char *dev_type,   /* --dev-type option */
         int topology,           /* one of the TOP_x values */
         const char *ifconfig_local_parm,           /* --ifconfig parm 1 */
         const char *ifconfig_remote_netmask_parm,  /* --ifconfig parm 2 */
         const char *ifconfig_ipv6_local_parm,      /* --ifconfig parm 1 IPv6 */
         int ifconfig_ipv6_netbits_parm,
         const char *ifconfig_ipv6_remote_parm,     /* --ifconfig parm 2 IPv6 */
         struct addrinfo *local_public,
         struct addrinfo *remote_public,
         const bool strict_warn,
         struct env_set *es,
         openvpn_net_ctx_t *ctx,
         struct tuntap *tt)
{
    if (!tt)
    {
        ALLOC_OBJ(tt, struct tuntap);
        clear_tuntap(tt);
    }

    tt->type = dev_type_enum(dev, dev_type);
    tt->topology = topology;

    if (ifconfig_local_parm && ifconfig_remote_netmask_parm)
    {
        bool tun = false;

        /*
         * We only handle TUN/TAP devices here, not --dev null devices.
         */
        tun = is_tun_p2p(tt);

        /*
         * Convert arguments to binary IPv4 addresses.
         */

        tt->local = getaddr(
            GETADDR_RESOLVE
            | GETADDR_HOST_ORDER
            | GETADDR_FATAL_ON_SIGNAL
            | GETADDR_FATAL,
            ifconfig_local_parm,
            0,
            NULL,
            NULL);

        tt->remote_netmask = getaddr(
            (tun ? GETADDR_RESOLVE : 0)
            | GETADDR_HOST_ORDER
            | GETADDR_FATAL_ON_SIGNAL
            | GETADDR_FATAL,
            ifconfig_remote_netmask_parm,
            0,
            NULL,
            NULL);

        /*
         * Look for common errors in --ifconfig parms
         */
        if (strict_warn)
        {
            struct addrinfo *curele;
            ifconfig_sanity_check(tt->type == DEV_TYPE_TUN, tt->remote_netmask, tt->topology);

            /*
             * If local_public or remote_public addresses are defined,
             * make sure they do not clash with our virtual subnet.
             */

            for (curele = local_public; curele; curele = curele->ai_next)
            {
                if (curele->ai_family == AF_INET)
                {
                    check_addr_clash("local",
                                     tt->type,
                                     ((struct sockaddr_in *)curele->ai_addr)->sin_addr.s_addr,
                                     tt->local,
                                     tt->remote_netmask);
                }
            }

            for (curele = remote_public; curele; curele = curele->ai_next)
            {
                if (curele->ai_family == AF_INET)
                {
                    check_addr_clash("remote",
                                     tt->type,
                                     ((struct sockaddr_in *)curele->ai_addr)->sin_addr.s_addr,
                                     tt->local,
                                     tt->remote_netmask);
                }
            }

            if (tt->type == DEV_TYPE_TAP || (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET))
            {
                check_subnet_conflict(tt->local, tt->remote_netmask, "TUN/TAP adapter");
            }
            else if (tt->type == DEV_TYPE_TUN)
            {
                check_subnet_conflict(tt->local, IPV4_NETMASK_HOST, "TUN/TAP adapter");
            }
        }

#ifdef _WIN32
        /*
         * Make sure that both ifconfig addresses are part of the
         * same .252 subnet.
         */
        if (tun)
        {
            verify_255_255_255_252(tt->local, tt->remote_netmask);
            tt->adapter_netmask = ~3;
        }
        else
        {
            tt->adapter_netmask = tt->remote_netmask;
        }
#endif

        tt->did_ifconfig_setup = true;
    }

    if (ifconfig_ipv6_local_parm && ifconfig_ipv6_remote_parm)
    {

        /*
         * Convert arguments to binary IPv6 addresses.
         */

        if (inet_pton( AF_INET6, ifconfig_ipv6_local_parm, &tt->local_ipv6 ) != 1
            || inet_pton( AF_INET6, ifconfig_ipv6_remote_parm, &tt->remote_ipv6 ) != 1)
        {
            msg( M_FATAL, "init_tun: problem converting IPv6 ifconfig addresses %s and %s to binary", ifconfig_ipv6_local_parm, ifconfig_ipv6_remote_parm );
        }
        tt->netbits_ipv6 = ifconfig_ipv6_netbits_parm;

        tt->did_ifconfig_ipv6_setup = true;
    }

    /*
     * Set environmental variables with ifconfig parameters.
     */
    if (es)
    {
        do_ifconfig_setenv(tt, es);
    }

    return tt;
}

/*
 * Platform specific tun initializations
 */
void
init_tun_post(struct tuntap *tt,
              const struct frame *frame,
              const struct tuntap_options *options)
{
    tt->options = *options;
#ifdef _WIN32
    if (tt->windows_driver == WINDOWS_DRIVER_DCO)
    {
        dco_start_tun(tt);
        return;
    }

    overlapped_io_init(&tt->reads, frame, FALSE);
    overlapped_io_init(&tt->writes, frame, TRUE);
    tt->adapter_index = TUN_ADAPTER_INDEX_INVALID;

    if (tt->windows_driver == WINDOWS_DRIVER_WINTUN)
    {
        tt->wintun_send_ring_handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                                                        PAGE_READWRITE,
                                                        0,
                                                        sizeof(struct tun_ring),
                                                        NULL);
        tt->wintun_receive_ring_handle = CreateFileMapping(INVALID_HANDLE_VALUE,
                                                           NULL,
                                                           PAGE_READWRITE,
                                                           0,
                                                           sizeof(struct tun_ring),
                                                           NULL);
        if ((tt->wintun_send_ring_handle == NULL) || (tt->wintun_receive_ring_handle == NULL))
        {
            msg(M_FATAL, "Cannot allocate memory for ring buffer");
        }

        tt->rw_handle.read = CreateEvent(NULL, FALSE, FALSE, NULL);
        tt->rw_handle.write = CreateEvent(NULL, FALSE, FALSE, NULL);

        if ((tt->rw_handle.read == NULL) || (tt->rw_handle.write == NULL))
        {
            msg(M_FATAL, "Cannot create events for ring buffer");
        }
    }
    else
    {
        tt->rw_handle.read = tt->reads.overlapped.hEvent;
        tt->rw_handle.write = tt->writes.overlapped.hEvent;
    }
#endif /* ifdef _WIN32 */
}

#if defined(_WIN32)    \
    || defined(TARGET_DARWIN) || defined(TARGET_NETBSD) || defined(TARGET_OPENBSD)

/* some of the platforms will auto-add a "network route" pointing
 * to the interface on "ifconfig tunX 2001:db8::1/64", others need
 * an extra call to "route add..."
 * -> helper function to simplify code below
 */
static void
add_route_connected_v6_net(struct tuntap *tt,
                           const struct env_set *es)
{
    struct route_ipv6 r6;

    CLEAR(r6);
    r6.network = tt->local_ipv6;
    r6.netbits = tt->netbits_ipv6;
    r6.gateway = tt->local_ipv6;
    r6.metric  = 0;                     /* connected route */
    r6.flags   = RT_DEFINED | RT_METRIC_DEFINED;
    add_route_ipv6(&r6, tt, 0, es, NULL);
}

void
delete_route_connected_v6_net(const struct tuntap *tt)
{
    struct route_ipv6 r6;

    CLEAR(r6);
    r6.network = tt->local_ipv6;
    r6.netbits = tt->netbits_ipv6;
    r6.gateway = tt->local_ipv6;
    r6.metric  = 0;                     /* connected route */
    r6.flags   = RT_DEFINED | RT_ADDED | RT_METRIC_DEFINED;
    route_ipv6_clear_host_bits(&r6);
    delete_route_ipv6(&r6, tt, 0, NULL, NULL);
}
#endif /* if defined(_WIN32) || defined(TARGET_DARWIN) || defined(TARGET_NETBSD) || defined(TARGET_OPENBSD) */

#if defined(TARGET_FREEBSD) || defined(TARGET_DRAGONFLY)  \
    || defined(TARGET_NETBSD) || defined(TARGET_OPENBSD)
/* we can't use true subnet mode on tun on all platforms, as that
 * conflicts with IPv6 (wants to use ND then, which we don't do),
 * but the OSes want "a remote address that is different from ours"
 * - so we construct one, normally the first in the subnet, but if
 * this is the same as ours, use the second one.
 * The actual address does not matter at all, as the tun interface
 * is still point to point and no layer 2 resolution is done...
 */

in_addr_t
create_arbitrary_remote( struct tuntap *tt )
{
    in_addr_t remote;

    remote = (tt->local & tt->remote_netmask) +1;

    if (remote == tt->local)
    {
        remote++;
    }

    return remote;
}
#endif

/**
 * do_ifconfig_ipv6 - perform platform specific ifconfig6 commands
 *
 * @param tt        the tuntap interface context
 * @param ifname    the human readable interface name
 * @param mtu       the MTU value to set the interface to
 * @param es        the environment to be used when executing the commands
 * @param ctx       the networking API opaque context
 */
static void
do_ifconfig_ipv6(struct tuntap *tt, const char *ifname, int tun_mtu,
                 const struct env_set *es, openvpn_net_ctx_t *ctx)
{
#if !defined(TARGET_LINUX)
    struct argv argv = argv_new();
    struct gc_arena gc = gc_new();
    const char *ifconfig_ipv6_local = print_in6_addr(tt->local_ipv6, 0, &gc);
#endif

#if defined(TARGET_LINUX)
    if (net_iface_mtu_set(ctx, ifname, tun_mtu) < 0)
    {
        msg(M_FATAL, "Linux can't set mtu (%d) on %s", tun_mtu, ifname);
    }

    if (net_iface_up(ctx, ifname, true) < 0)
    {
        msg(M_FATAL, "Linux can't bring %s up", ifname);
    }

    if (net_addr_v6_add(ctx, ifname, &tt->local_ipv6,
                        tt->netbits_ipv6) < 0)
    {
        msg(M_FATAL, "Linux can't add IPv6 to interface %s", ifname);
    }
#elif defined(TARGET_ANDROID)
    char out6[64];

    openvpn_snprintf(out6, sizeof(out6), "%s/%d %d",
                     ifconfig_ipv6_local, tt->netbits_ipv6, tun_mtu);
    management_android_control(management, "IFCONFIG6", out6);
#elif defined(TARGET_SOLARIS)
    argv_printf(&argv, "%s %s inet6 unplumb", IFCONFIG_PATH, ifname);
    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, es, 0, NULL);

    if (tt->type == DEV_TYPE_TUN)
    {
        const char *ifconfig_ipv6_remote = print_in6_addr(tt->remote_ipv6, 0, &gc);

        argv_printf(&argv, "%s %s inet6 plumb %s/%d %s mtu %d up",
                    IFCONFIG_PATH, ifname, ifconfig_ipv6_local,
                    tt->netbits_ipv6, ifconfig_ipv6_remote, tun_mtu);
    }
    else /* tap mode */
    {
        /* base IPv6 tap interface needs to be brought up first */
        argv_printf(&argv, "%s %s inet6 plumb up", IFCONFIG_PATH, ifname);
        argv_msg(M_INFO, &argv);

        if (!openvpn_execve_check(&argv, es, 0,
                                  "Solaris ifconfig IPv6 (prepare) failed"))
        {
            solaris_error_close(tt, es, ifname, true);
        }

        /* we might need to do "ifconfig %s inet6 auto-dhcp drop"
         * after the system has noticed the interface and fired up
         * the DHCPv6 client - but this takes quite a while, and the
         * server will ignore the DHCPv6 packets anyway.  So we don't.
         */

        /* static IPv6 addresses need to go to a subinterface (tap0:1)
         * and we cannot set an mtu here (must go to the "parent")
         */
        argv_printf(&argv, "%s %s inet6 addif %s/%d up", IFCONFIG_PATH,
                    ifname, ifconfig_ipv6_local, tt->netbits_ipv6 );
    }
    argv_msg(M_INFO, &argv);

    if (!openvpn_execve_check(&argv, es, 0, "Solaris ifconfig IPv6 failed"))
    {
        solaris_error_close(tt, es, ifname, true);
    }

    if (tt->type != DEV_TYPE_TUN)
    {
        argv_printf(&argv, "%s %s inet6 mtu %d", IFCONFIG_PATH,
                    ifname, tun_mtu);
        argv_msg(M_INFO, &argv);
        openvpn_execve_check(&argv, es, 0, "Solaris ifconfig IPv6 mtu failed");
    }
#elif defined(TARGET_OPENBSD) || defined(TARGET_NETBSD) \
    || defined(TARGET_DARWIN) || defined(TARGET_FREEBSD) \
    || defined(TARGET_DRAGONFLY)
    argv_printf(&argv, "%s %s inet6 %s/%d mtu %d up", IFCONFIG_PATH, ifname,
                ifconfig_ipv6_local, tt->netbits_ipv6, tun_mtu);
    argv_msg(M_INFO, &argv);

    openvpn_execve_check(&argv, es, S_FATAL,
                         "generic BSD ifconfig inet6 failed");

#if defined(TARGET_FREEBSD) && __FreeBSD_version >= 1200000 \
    && __FreeBSD_version < 1300000
    /* On FreeBSD 12.0-12.4, there is ipv6_activate_all_interfaces="YES"
     * in rc.conf, which is not set by default.  If it is *not* set,
     * "all new interfaces that are not already up" are configured by
     * devd -> /etc/pccard_ether -> /etc/network.subr as "inet6 ifdisabled".
     *
     * The "is this interface already up?" test is a non-zero time window
     * which we manage to hit with our ifconfig often enough to cause
     * frequent fails in the openvpn test environment.
     *
     * Thus: assume that the system might interfere, wait for things to
     * settle (it's a very short time window), and remove -ifdisable again.
     *
     * See: https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=248172
     */
    sleep(1);
    argv_printf(&argv, "%s %s inet6 -ifdisabled", IFCONFIG_PATH, ifname);
    argv_msg(M_INFO, &argv);

    openvpn_execve_check(&argv, es, S_FATAL,
                         "FreeBSD BSD 'ifconfig inet6 -ifdisabled' failed");
#endif

#if defined(TARGET_OPENBSD) || defined(TARGET_NETBSD) \
    || defined(TARGET_DARWIN)
    /* and, hooray, we explicitly need to add a route... */
    add_route_connected_v6_net(tt, es);
#endif
#elif defined(TARGET_AIX)
    argv_printf(&argv, "%s %s inet6 %s/%d mtu %d up", IFCONFIG_PATH, ifname,
                ifconfig_ipv6_local, tt->netbits_ipv6, tun_mtu);
    argv_msg(M_INFO, &argv);

    /* AIX ifconfig will complain if it can't find ODM path in env */
    es = env_set_create(NULL);
    env_set_add(es, "ODMDIR=/etc/objrepos");

    openvpn_execve_check(&argv, es, S_FATAL,
                         "generic BSD ifconfig inet6 failed");

    env_set_destroy(es);
#elif defined (_WIN32)
    if (tt->options.ip_win32_type == IPW32_SET_MANUAL)
    {
        msg(M_INFO, "******** NOTE:  Please manually set the v6 IP of '%s' to %s (if it is not already set)",
            ifname, ifconfig_ipv6_local);
    }
    else if (tt->options.msg_channel)
    {
        do_address_service(true, AF_INET6, tt);
        if (tt->type == DEV_TYPE_TUN)
        {
            add_route_connected_v6_net(tt, es);
        }
        do_dns_service(true, AF_INET6, tt);
        do_set_mtu_service(tt, AF_INET6, tun_mtu);
        /* If IPv4 is not enabled, set DNS domain here */
        if (!tt->did_ifconfig_setup)
        {
            do_dns_domain_service(true, tt);
        }
    }
    else
    {
        /* example: netsh interface ipv6 set address 42
         *                  2001:608:8003::d/bits store=active
         */

        /* in TUN mode, we only simulate a subnet, so the interface
         * is configured with /128 + a route to fe80::8.  In TAP mode,
         * the correct netbits must be set, and no on-link route
         */
        int netbits = (tt->type == DEV_TYPE_TUN) ? 128 : tt->netbits_ipv6;

        argv_printf(&argv, "%s%s interface ipv6 set address %lu %s/%d store=active",
                    get_win_sys_path(), NETSH_PATH_SUFFIX, tt->adapter_index,
                    ifconfig_ipv6_local, netbits);
        netsh_command(&argv, 4, M_FATAL);
        if (tt->type == DEV_TYPE_TUN)
        {
            add_route_connected_v6_net(tt, es);
        }
        /* set ipv6 dns servers if any are specified */
        netsh_set_dns6_servers(tt->options.dns6, tt->options.dns6_len, tt->adapter_index);
        windows_set_mtu(tt->adapter_index, AF_INET6, tun_mtu);

        if (!tt->did_ifconfig_setup)
        {
            do_dns_domain_wmic(true, tt);
        }
    }
#else /* platforms we have no IPv6 code for */
    msg(M_FATAL, "Sorry, but I don't know how to do IPv6 'ifconfig' commands on this operating system.  You should ifconfig your TUN/TAP device manually or use an --up script.");
#endif /* outer "if defined(TARGET_xxx)" conditional */

#if !defined(TARGET_LINUX)
    gc_free(&gc);
    argv_free(&argv);
#endif
}

/**
 * do_ifconfig_ipv4 - perform platform specific ifconfig commands
 *
 * @param tt        the tuntap interface context
 * @param ifname    the human readable interface name
 * @param mtu       the MTU value to set the interface to
 * @param es        the environment to be used when executing the commands
 * @param ctx       the networking API opaque context
 */
static void
do_ifconfig_ipv4(struct tuntap *tt, const char *ifname, int tun_mtu,
                 const struct env_set *es, openvpn_net_ctx_t *ctx)
{
#if !defined(_WIN32) && !defined(TARGET_ANDROID)
    /*
     * We only handle TUN/TAP devices here, not --dev null devices.
     */
    bool tun = is_tun_p2p(tt);
#endif

#if !defined(TARGET_LINUX)
    const char *ifconfig_local = NULL;
    const char *ifconfig_remote_netmask = NULL;
    struct argv argv = argv_new();
    struct gc_arena gc = gc_new();

    /*
     * Set ifconfig parameters
     */
    ifconfig_local = print_in_addr_t(tt->local, 0, &gc);
    ifconfig_remote_netmask = print_in_addr_t(tt->remote_netmask, 0, &gc);
#endif

#if defined(TARGET_LINUX)
    if (net_iface_mtu_set(ctx, ifname, tun_mtu) < 0)
    {
        msg(M_FATAL, "Linux can't set mtu (%d) on %s", tun_mtu, ifname);
    }

    if (net_iface_up(ctx, ifname, true) < 0)
    {
        msg(M_FATAL, "Linux can't bring %s up", ifname);
    }

    if (tun)
    {
        if (net_addr_ptp_v4_add(ctx, ifname, &tt->local,
                                &tt->remote_netmask) < 0)
        {
            msg(M_FATAL, "Linux can't add IP to interface %s", ifname);
        }
    }
    else
    {
        if (net_addr_v4_add(ctx, ifname, &tt->local,
                            netmask_to_netbits2(tt->remote_netmask)) < 0)
        {
            msg(M_FATAL, "Linux can't add IP to interface %s", ifname);
        }
    }
#elif defined(TARGET_ANDROID)
    char out[64];

    char *top;
    switch (tt->topology)
    {
        case TOP_NET30:
            top = "net30";
            break;

        case TOP_P2P:
            top = "p2p";
            break;

        case TOP_SUBNET:
            top = "subnet";
            break;

        default:
            top = "undef";
    }

    openvpn_snprintf(out, sizeof(out), "%s %s %d %s", ifconfig_local,
                     ifconfig_remote_netmask, tun_mtu, top);
    management_android_control(management, "IFCONFIG", out);

#elif defined(TARGET_SOLARIS)
    /* Solaris 2.6 (and 7?) cannot set all parameters in one go...
     * example:
     *    ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 up
     *    ifconfig tun2 netmask 255.255.255.255
     */
    if (tun)
    {
        argv_printf(&argv, "%s %s %s %s mtu %d up", IFCONFIG_PATH, ifname,
                    ifconfig_local, ifconfig_remote_netmask, tun_mtu);

        argv_msg(M_INFO, &argv);
        if (!openvpn_execve_check(&argv, es, 0, "Solaris ifconfig phase-1 failed"))
        {
            solaris_error_close(tt, es, ifname, false);
        }

        argv_printf(&argv, "%s %s netmask 255.255.255.255", IFCONFIG_PATH,
                    ifname);
    }
    else if (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET)
    {
        argv_printf(&argv, "%s %s %s %s netmask %s mtu %d up", IFCONFIG_PATH,
                    ifname, ifconfig_local, ifconfig_local,
                    ifconfig_remote_netmask, tun_mtu);
    }
    else
    {
        argv_printf(&argv, "%s %s %s netmask %s up",
                    IFCONFIG_PATH, ifname, ifconfig_local,
                    ifconfig_remote_netmask);
    }

    argv_msg(M_INFO, &argv);
    if (!openvpn_execve_check(&argv, es, 0, "Solaris ifconfig phase-2 failed"))
    {
        solaris_error_close(tt, es, ifname, false);
    }

    if (!tun && tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET)
    {
        /* Add a network route for the local tun interface */
        struct route_ipv4 r;
        CLEAR(r);
        r.flags = RT_DEFINED | RT_METRIC_DEFINED;
        r.network = tt->local & tt->remote_netmask;
        r.netmask = tt->remote_netmask;
        r.gateway = tt->local;
        r.metric = 0;
        add_route(&r, tt, 0, NULL, es, NULL);
    }

#elif defined(TARGET_OPENBSD)

    in_addr_t remote_end;           /* for "virtual" subnet topology */

    /*
     * On OpenBSD, tun interfaces are persistent if created with
     * "ifconfig tunX create", and auto-destroyed if created by
     * opening "/dev/tunX" (so we just use the /dev/tunX)
     */

    /* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
    if (tun)
    {
        argv_printf(&argv,
                    "%s %s %s %s mtu %d netmask 255.255.255.255 up -link0",
                    IFCONFIG_PATH, ifname, ifconfig_local,
                    ifconfig_remote_netmask, tun_mtu);
    }
    else if (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET)
    {
        remote_end = create_arbitrary_remote( tt );
        argv_printf(&argv, "%s %s %s %s mtu %d netmask %s up -link0",
                    IFCONFIG_PATH, ifname, ifconfig_local,
                    print_in_addr_t(remote_end, 0, &gc), tun_mtu,
                    ifconfig_remote_netmask);
    }
    else
    {
        argv_printf(&argv, "%s %s %s netmask %s mtu %d link0",
                    IFCONFIG_PATH, ifname, ifconfig_local,
                    ifconfig_remote_netmask, tun_mtu);
    }
    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, es, S_FATAL, "OpenBSD ifconfig failed");

    /* Add a network route for the local tun interface */
    if (!tun && tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET)
    {
        struct route_ipv4 r;
        CLEAR(r);
        r.flags = RT_DEFINED;
        r.network = tt->local & tt->remote_netmask;
        r.netmask = tt->remote_netmask;
        r.gateway = remote_end;
        add_route(&r, tt, 0, NULL, es, NULL);
    }

#elif defined(TARGET_NETBSD)
    in_addr_t remote_end = INADDR_ANY;  /* for "virtual" subnet topology */

    if (tun)
    {
        argv_printf(&argv, "%s %s %s %s mtu %d netmask 255.255.255.255 up",
                    IFCONFIG_PATH, ifname, ifconfig_local,
                    ifconfig_remote_netmask, tun_mtu);
    }
    else if (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET)
    {
        remote_end = create_arbitrary_remote(tt);
        argv_printf(&argv, "%s %s %s %s mtu %d netmask %s up", IFCONFIG_PATH,
                    ifname, ifconfig_local, print_in_addr_t(remote_end, 0, &gc),
                    tun_mtu, ifconfig_remote_netmask);
    }
    else
    {
        /*
         * NetBSD has distinct tun and tap devices
         * so we don't need the "link0" extra parameter to specify we want to do
         * tunneling at the ethernet level
         */
        argv_printf(&argv, "%s %s %s netmask %s mtu %d",
                    IFCONFIG_PATH, ifname, ifconfig_local,
                    ifconfig_remote_netmask, tun_mtu);
    }
    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, es, S_FATAL, "NetBSD ifconfig failed");

    /* Add a network route for the local tun interface */
    if (!tun && tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET)
    {
        struct route_ipv4 r;
        CLEAR(r);
        r.flags = RT_DEFINED;
        r.network = tt->local & tt->remote_netmask;
        r.netmask = tt->remote_netmask;
        r.gateway = remote_end;
        add_route(&r, tt, 0, NULL, es, NULL);
    }

#elif defined(TARGET_DARWIN)
    /*
     * Darwin (i.e. Mac OS X) seems to exhibit similar behaviour to OpenBSD...
     */

    argv_printf(&argv, "%s %s delete", IFCONFIG_PATH, ifname);
    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, es, 0, NULL);
    msg(M_INFO,
        "NOTE: Tried to delete pre-existing tun/tap instance -- No Problem if failure");


    /* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
    if (tun)
    {
        argv_printf(&argv, "%s %s %s %s mtu %d netmask 255.255.255.255 up",
                    IFCONFIG_PATH, ifname, ifconfig_local,
                    ifconfig_remote_netmask, tun_mtu);
    }
    else
    {
        if (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET)
        {
            argv_printf(&argv, "%s %s %s %s netmask %s mtu %d up",
                        IFCONFIG_PATH, ifname, ifconfig_local, ifconfig_local,
                        ifconfig_remote_netmask, tun_mtu);
        }
        else
        {
            argv_printf(&argv, "%s %s %s netmask %s mtu %d up", IFCONFIG_PATH,
                        ifname, ifconfig_local, ifconfig_remote_netmask,
                        tun_mtu);
        }
    }

    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, es, S_FATAL, "Mac OS X ifconfig failed");

    /* Add a network route for the local tun interface */
    if (!tun && tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET)
    {
        struct route_ipv4 r;
        CLEAR(r);
        r.flags = RT_DEFINED;
        r.network = tt->local & tt->remote_netmask;
        r.netmask = tt->remote_netmask;
        r.gateway = tt->local;
        add_route(&r, tt, 0, NULL, es, NULL);
    }

#elif defined(TARGET_FREEBSD) || defined(TARGET_DRAGONFLY)

    /* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
    if (tun)       /* point-to-point tun */
    {
        argv_printf(&argv, "%s %s %s %s mtu %d netmask 255.255.255.255 up",
                    IFCONFIG_PATH, ifname, ifconfig_local,
                    ifconfig_remote_netmask, tun_mtu);
    }
    else            /* tun with topology subnet and tap mode (always subnet) */
    {
        int netbits = netmask_to_netbits2(tt->remote_netmask);
        argv_printf(&argv, "%s %s %s/%d mtu %d up", IFCONFIG_PATH,
                    ifname, ifconfig_local, netbits, tun_mtu );
    }

    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, es, S_FATAL, "FreeBSD ifconfig failed");

#elif defined(TARGET_AIX)
    {
        /* AIX ifconfig will complain if it can't find ODM path in env */
        struct env_set *aix_es = env_set_create(NULL);
        env_set_add( aix_es, "ODMDIR=/etc/objrepos" );

        if (tun)
        {
            msg(M_FATAL, "no tun support on AIX (canthappen)");
        }

        /* example: ifconfig tap0 172.30.1.1 netmask 255.255.254.0 up */
        argv_printf(&argv, "%s %s %s netmask %s mtu %d up", IFCONFIG_PATH,
                    ifname, ifconfig_local, ifconfig_remote_netmask, tun_mtu);

        argv_msg(M_INFO, &argv);
        openvpn_execve_check(&argv, aix_es, S_FATAL, "AIX ifconfig failed");

        env_set_destroy(aix_es);
    }
#elif defined (_WIN32)
    if (tt->options.ip_win32_type == IPW32_SET_MANUAL)
    {
        msg(M_INFO,
            "******** NOTE:  Please manually set the IP/netmask of '%s' to %s/%s (if it is not already set)",
            ifname, ifconfig_local,
            ifconfig_remote_netmask);
    }
    else if (tt->options.ip_win32_type == IPW32_SET_DHCP_MASQ || tt->options.ip_win32_type == IPW32_SET_ADAPTIVE)
    {
        /* Let the DHCP configure the interface. */
    }
    else if (tt->options.msg_channel)
    {
        do_address_service(true, AF_INET, tt);
        do_dns_service(true, AF_INET, tt);
        do_dns_domain_service(true, tt);
        do_wins_service(true, tt);
    }
    else
    {
        if (tt->options.ip_win32_type == IPW32_SET_NETSH)
        {
            netsh_ifconfig(&tt->options, tt->adapter_index, tt->local,
                           tt->adapter_netmask, NI_IP_NETMASK | NI_OPTIONS);
        }

        do_dns_domain_wmic(true, tt);
    }


    if (tt->options.msg_channel)
    {
        do_set_mtu_service(tt, AF_INET, tun_mtu);
    }
    else
    {
        windows_set_mtu(tt->adapter_index, AF_INET, tun_mtu);
    }
#else  /* if defined(TARGET_LINUX) */
    msg(M_FATAL, "Sorry, but I don't know how to do 'ifconfig' commands on this operating system.  You should ifconfig your TUN/TAP device manually or use an --up script.");
#endif /* if defined(TARGET_LINUX) */

#if !defined(TARGET_LINUX)
    gc_free(&gc);
    argv_free(&argv);
#endif
}

/* execute the ifconfig command through the shell */
void
do_ifconfig(struct tuntap *tt, const char *ifname, int tun_mtu,
            const struct env_set *es, openvpn_net_ctx_t *ctx)
{
    msg(D_LOW, "do_ifconfig, ipv4=%d, ipv6=%d", tt->did_ifconfig_setup,
        tt->did_ifconfig_ipv6_setup);

#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_set_state(management,
                             OPENVPN_STATE_ASSIGN_IP,
                             NULL,
                             &tt->local,
                             &tt->local_ipv6,
                             NULL,
                             NULL);
    }
#endif

    if (tt->did_ifconfig_setup)
    {
        do_ifconfig_ipv4(tt, ifname, tun_mtu, es, ctx);
    }

    if (tt->did_ifconfig_ipv6_setup)
    {
        do_ifconfig_ipv6(tt, ifname, tun_mtu, es, ctx);
    }

    /* release resources potentially allocated during interface setup */
    net_ctx_free(ctx);
}

static void
undo_ifconfig_ipv4(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
#if defined(TARGET_LINUX)
    int netbits = netmask_to_netbits2(tt->remote_netmask);

    if (is_tun_p2p(tt))
    {
        if (net_addr_ptp_v4_del(ctx, tt->actual_name, &tt->local,
                                &tt->remote_netmask) < 0)
        {
            msg(M_WARN, "Linux can't del IP from iface %s",
                tt->actual_name);
        }
    }
    else
    {
        if (net_addr_v4_del(ctx, tt->actual_name, &tt->local, netbits) < 0)
        {
            msg(M_WARN, "Linux can't del IP from iface %s",
                tt->actual_name);
        }
    }
#elif defined(TARGET_FREEBSD)
    struct gc_arena gc = gc_new();
    const char *ifconfig_local = print_in_addr_t(tt->local, 0, &gc);
    struct argv argv = argv_new();

    argv_printf(&argv, "%s %s %s -alias", IFCONFIG_PATH,
                tt->actual_name, ifconfig_local);
    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, NULL, 0, "FreeBSD ip addr del failed");

    argv_free(&argv);
    gc_free(&gc);
#endif /* if defined(TARGET_LINUX) */
       /* Empty for _WIN32 and all other unixoid platforms */
}

static void
undo_ifconfig_ipv6(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
#if defined(TARGET_LINUX)
    if (net_addr_v6_del(ctx, tt->actual_name, &tt->local_ipv6,
                        tt->netbits_ipv6) < 0)
    {
        msg(M_WARN, "Linux can't del IPv6 from iface %s", tt->actual_name);
    }
#elif defined(TARGET_FREEBSD)
    struct gc_arena gc = gc_new();
    const char *ifconfig_ipv6_local = print_in6_addr(tt->local_ipv6, 0, &gc);
    struct argv argv = argv_new();

    argv_printf(&argv, "%s %s inet6 %s/%d -alias", IFCONFIG_PATH,
                tt->actual_name, ifconfig_ipv6_local, tt->netbits_ipv6);

    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, NULL, 0, "FreeBSD ip -6 addr del failed");

    argv_free(&argv);
    gc_free(&gc);
#endif /* if defined(TARGET_LINUX) */
       /* Empty for _WIN32 and all other unixoid platforms */
}

void
undo_ifconfig(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    if (tt->type != DEV_TYPE_NULL)
    {
        if (tt->did_ifconfig_setup)
        {
            undo_ifconfig_ipv4(tt, ctx);
        }

        if (tt->did_ifconfig_ipv6_setup)
        {
            undo_ifconfig_ipv6(tt, ctx);
        }

        /* release resources potentially allocated during undo */
        net_ctx_reset(ctx);
    }
}

static void
clear_tuntap(struct tuntap *tuntap)
{
    CLEAR(*tuntap);
#ifdef _WIN32
    tuntap->hand = NULL;
#else
    tuntap->fd = -1;
#endif
#ifdef TARGET_SOLARIS
    tuntap->ip_fd = -1;
#endif
}

static void
open_null(struct tuntap *tt)
{
    tt->actual_name = string_alloc("null", NULL);
}


#if defined (TARGET_OPENBSD) || (defined(TARGET_DARWIN) && HAVE_NET_IF_UTUN_H)

/*
 * OpenBSD and Mac OS X when using utun
 * have a slightly incompatible TUN device from
 * the rest of the world, in that it prepends a
 * uint32 to the beginning of the IP header
 * to designate the protocol (why not just
 * look at the version field in the IP header to
 * determine v4 or v6?).
 *
 * We strip off this field on reads and
 * put it back on writes.
 *
 * I have not tested TAP devices on OpenBSD,
 * but I have conditionalized the special
 * TUN handling code described above to
 * go away for TAP devices.
 */

#include <netinet/ip.h>
#include <sys/uio.h>

static inline int
header_modify_read_write_return(int len)
{
    if (len > 0)
    {
        return len > sizeof(u_int32_t) ? len - sizeof(u_int32_t) : 0;
    }
    else
    {
        return len;
    }
}

int
write_tun_header(struct tuntap *tt, uint8_t *buf, int len)
{
    if (tt->type == DEV_TYPE_TUN)
    {
        u_int32_t type;
        struct iovec iv[2];
        struct openvpn_iphdr *iph;

        iph = (struct openvpn_iphdr *) buf;

        if (OPENVPN_IPH_GET_VER(iph->version_len) == 6)
        {
            type = htonl(AF_INET6);
        }
        else
        {
            type = htonl(AF_INET);
        }

        iv[0].iov_base = &type;
        iv[0].iov_len = sizeof(type);
        iv[1].iov_base = buf;
        iv[1].iov_len = len;

        return header_modify_read_write_return(writev(tt->fd, iv, 2));
    }
    else
    {
        return write(tt->fd, buf, len);
    }
}

int
read_tun_header(struct tuntap *tt, uint8_t *buf, int len)
{
    if (tt->type == DEV_TYPE_TUN)
    {
        u_int32_t type;
        struct iovec iv[2];

        iv[0].iov_base = &type;
        iv[0].iov_len = sizeof(type);
        iv[1].iov_base = buf;
        iv[1].iov_len = len;

        return header_modify_read_write_return(readv(tt->fd, iv, 2));
    }
    else
    {
        return read(tt->fd, buf, len);
    }
}
#endif /* if defined (TARGET_OPENBSD) || (defined(TARGET_DARWIN) && HAVE_NET_IF_UTUN_H) */

bool
tun_name_is_fixed(const char *dev)
{
    return has_digit(dev);
}

#if defined(TARGET_LINUX) || defined(TARGET_FREEBSD)
static bool
tun_dco_enabled(struct tuntap *tt)
{
    return !tt->options.disable_dco;
}
#endif


#if !(defined(_WIN32) || defined(TARGET_LINUX))
static void
open_tun_generic(const char *dev, const char *dev_type, const char *dev_node,
                 struct tuntap *tt)
{
    char tunname[256];
    char dynamic_name[256];
    bool dynamic_opened = false;

    if (tt->type == DEV_TYPE_NULL)
    {
        open_null(tt);
    }
    else
    {
        /*
         * --dev-node specified, so open an explicit device node
         */
        if (dev_node)
        {
            openvpn_snprintf(tunname, sizeof(tunname), "%s", dev_node);
        }
        else
        {
            /*
             * dynamic open is indicated by --dev specified without
             * explicit unit number.  Try opening /dev/[dev]n
             * where n = [0, 255].
             */

            if (!tun_name_is_fixed(dev))
            {
                for (int i = 0; i < 256; ++i)
                {
                    openvpn_snprintf(tunname, sizeof(tunname),
                                     "/dev/%s%d", dev, i);
                    openvpn_snprintf(dynamic_name, sizeof(dynamic_name),
                                     "%s%d", dev, i);
                    if ((tt->fd = open(tunname, O_RDWR)) > 0)
                    {
                        dynamic_opened = true;
                        break;
                    }
                    msg(D_READ_WRITE | M_ERRNO, "Tried opening %s (failed)", tunname);
                }
                if (!dynamic_opened)
                {
                    msg(M_FATAL, "Cannot allocate TUN/TAP dev dynamically");
                }
            }
            /*
             * explicit unit number specified
             */
            else
            {
                openvpn_snprintf(tunname, sizeof(tunname), "/dev/%s", dev);
            }
        }

        if (!dynamic_opened)
        {
            /* has named device existed before? if so, don't destroy at end */
            if (if_nametoindex( dev ) > 0)
            {
                msg(M_INFO, "TUN/TAP device %s exists previously, keep at program end", dev );
                tt->persistent_if = true;
            }

            if ((tt->fd = open(tunname, O_RDWR)) < 0)
            {
                msg(M_ERR, "Cannot open TUN/TAP dev %s", tunname);
            }
        }

        set_nonblock(tt->fd);
        set_cloexec(tt->fd); /* don't pass fd to scripts */
        msg(M_INFO, "TUN/TAP device %s opened", tunname);

        /* tt->actual_name is passed to up and down scripts and used as the ifconfig dev name */
        tt->actual_name = string_alloc(dynamic_opened ? dynamic_name : dev, NULL);
    }
}
#endif /* !_WIN32 && !TARGET_LINUX && !TARGET_FREEBSD*/

#if defined(TARGET_LINUX) || defined(TARGET_FREEBSD)
static void
open_tun_dco_generic(const char *dev, const char *dev_type,
                     struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    char dynamic_name[256];
    bool dynamic_opened = false;

    if (tt->type == DEV_TYPE_NULL)
    {
        open_null(tt);
        return;
    }

    /*
     * unlike "open_tun_generic()", DCO on Linux and FreeBSD follows
     * the device naming model of "non-DCO linux", that is:
     *   --dev tun         -> try tun0, tun1, ... tun255, use first free
     *   --dev <anything>  -> (try to) create a tun device named "anything"
     * ("--dev tap" and "--dev null" are caught earlier and not handled here)
     */

    if (strcmp(dev, "tun") == 0)
    {
        for (int i = 0; i < 256; ++i)
        {
            openvpn_snprintf(dynamic_name, sizeof(dynamic_name),
                             "%s%d", dev, i);
            int ret = open_tun_dco(tt, ctx, dynamic_name);
            if (ret == 0)
            {
                dynamic_opened = true;
                msg(M_INFO, "DCO device %s opened", dynamic_name);
                break;
            }
            /* "permission denied" won't succeed if we try 256 times */
            else if (ret == -EPERM)
            {
                break;
            }
        }
        if (!dynamic_opened)
        {
            msg(M_FATAL, "Cannot allocate DCO dev dynamically");
        }
        /* tt->actual_name is passed to up and down scripts and used as
         * the ifconfig dev name */
        tt->actual_name = string_alloc(dynamic_name, NULL);
    }
    /*
     * explicit unit number specified
     */
    else
    {
        int ret = open_tun_dco(tt, ctx, dev);
        if (ret == -EEXIST)
        {
            msg(M_INFO, "DCO device %s already exists, won't be destroyed at shutdown",
                dev);
            tt->persistent_if = true;
        }
        else if (ret < 0)
        {
            msg(M_ERR, "Cannot open DCO device %s: %s (%d)", dev,
                strerror(-ret), ret);
        }
        else
        {
            msg(M_INFO, "DCO device %s opened", dev);
        }

        /* tt->actual_name is passed to up and down scripts and used as the ifconfig dev name */
        tt->actual_name = string_alloc(dev, NULL);
    }
}
#endif /* TARGET_LINUX || TARGET_FREEBSD*/

#if !defined(_WIN32)
static void
close_tun_generic(struct tuntap *tt)
{
    if (tt->fd >= 0)
    {
        close(tt->fd);
    }

    free(tt->actual_name);
    clear_tuntap(tt);
}
#endif /* !_WIN32 */

#if defined (TARGET_ANDROID)
void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
#define ANDROID_TUNNAME "vpnservice-tun"
    struct user_pass up;
    struct gc_arena gc = gc_new();
    bool opentun;

    int oldtunfd = tt->fd;

    /* Prefer IPv6 DNS servers,
     * Android will use the DNS server in the order we specify*/
    for (int i = 0; i < tt->options.dns6_len; i++)
    {
        management_android_control(management, "DNS6SERVER",
                                   print_in6_addr(tt->options.dns6[i], 0, &gc));
    }

    for (int i = 0; i < tt->options.dns_len; i++)
    {
        management_android_control(management, "DNSSERVER",
                                   print_in_addr_t(tt->options.dns[i], 0, &gc));
    }

    if (tt->options.domain)
    {
        management_android_control(management, "DNSDOMAIN", tt->options.domain);
    }

    if (tt->options.http_proxy)
    {
        struct buffer buf = alloc_buf_gc(strlen(tt->options.http_proxy) + 20, &gc);
        buf_printf(&buf, "%s %d", tt->options.http_proxy, tt->options.http_proxy_port);
        management_android_control(management, "HTTPPROXY", BSTR(&buf));
    }

    int android_method = managment_android_persisttun_action(management);

    if (oldtunfd >=0  && android_method == ANDROID_KEEP_OLD_TUN)
    {
        /* keep the old fd */
        opentun = true;
    }
    else
    {
        opentun = management_android_control(management, "OPENTUN", dev);
        /* Pick up the fd from management interface after calling the
         * OPENTUN command */
        tt->fd = management->connection.lastfdreceived;
        management->connection.lastfdreceived = -1;
    }

    if (oldtunfd >= 0 && android_method == ANDROID_OPEN_BEFORE_CLOSE)
    {
        close(oldtunfd);
    }

    /* Set the actual name to a dummy name */
    tt->actual_name = string_alloc(ANDROID_TUNNAME, NULL);

    if ((tt->fd < 0) || !opentun)
    {
        msg(M_ERR, "ERROR: Cannot open TUN");
    }

    gc_free(&gc);
}

void
close_tun(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    ASSERT(tt);

    close_tun_generic(tt);
    free(tt);
}

int
write_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    return write(tt->fd, buf, len);
}

int
read_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    return read(tt->fd, buf, len);
}

#elif defined(TARGET_LINUX)

#ifndef HAVE_LINUX_SOCKIOS_H
#error header file linux/sockios.h required
#endif

#if !PEDANTIC

void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
    struct ifreq ifr;

    /*
     * We handle --dev null specially, we do not open /dev/null for this.
     */
    if (tt->type == DEV_TYPE_NULL)
    {
        open_null(tt);
    }
    else if (tun_dco_enabled(tt))
    {
        open_tun_dco_generic(dev, dev_type, tt, ctx);
    }
    else
    {
        /*
         * Process --dev-node
         */
        const char *node = dev_node;
        if (!node)
        {
            node = "/dev/net/tun";
        }

        /*
         * Open the interface
         */
        if ((tt->fd = open(node, O_RDWR)) < 0)
        {
            msg(M_ERR, "ERROR: Cannot open TUN/TAP dev %s", node);
        }

        /*
         * Process --tun-ipv6
         */
        CLEAR(ifr);
        ifr.ifr_flags = IFF_NO_PI;

#if defined(IFF_ONE_QUEUE) && defined(SIOCSIFTXQLEN)
        ifr.ifr_flags |= IFF_ONE_QUEUE;
#endif

        /*
         * Figure out if tun or tap device
         */
        if (tt->type == DEV_TYPE_TUN)
        {
            ifr.ifr_flags |= IFF_TUN;
        }
        else if (tt->type == DEV_TYPE_TAP)
        {
            ifr.ifr_flags |= IFF_TAP;
        }
        else
        {
            msg(M_FATAL, "I don't recognize device %s as a tun or tap device",
                dev);
        }

        /*
         * Set an explicit name, if --dev is not tun or tap
         */
        if (strcmp(dev, "tun") && strcmp(dev, "tap"))
        {
            strncpynt(ifr.ifr_name, dev, IFNAMSIZ);
        }

        /*
         * Use special ioctl that configures tun/tap device with the parms
         * we set in ifr
         */
        if (ioctl(tt->fd, TUNSETIFF, (void *) &ifr) < 0)
        {
            msg(M_ERR, "ERROR: Cannot ioctl TUNSETIFF %s", dev);
        }

        msg(M_INFO, "TUN/TAP device %s opened", ifr.ifr_name);

        /*
         * Try making the TX send queue bigger
         */
#if defined(IFF_ONE_QUEUE) && defined(SIOCSIFTXQLEN)
        if (tt->options.txqueuelen)
        {
            struct ifreq netifr;
            int ctl_fd;

            if ((ctl_fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
            {
                CLEAR(netifr);
                strncpynt(netifr.ifr_name, ifr.ifr_name, IFNAMSIZ);
                netifr.ifr_qlen = tt->options.txqueuelen;
                if (ioctl(ctl_fd, SIOCSIFTXQLEN, (void *) &netifr) >= 0)
                {
                    msg(D_OSBUF, "TUN/TAP TX queue length set to %d", tt->options.txqueuelen);
                }
                else
                {
                    msg(M_WARN | M_ERRNO, "Note: Cannot set tx queue length on %s", ifr.ifr_name);
                }
                close(ctl_fd);
            }
            else
            {
                msg(M_WARN | M_ERRNO, "Note: Cannot open control socket on %s", ifr.ifr_name);
            }
        }
#endif /* if defined(IFF_ONE_QUEUE) && defined(SIOCSIFTXQLEN) */

        set_nonblock(tt->fd);
        set_cloexec(tt->fd);
        tt->actual_name = string_alloc(ifr.ifr_name, NULL);
    }
    return;
}

#else  /* if !PEDANTIC */

void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
    ASSERT(0);
}

#endif /* !PEDANTIC */

#ifdef ENABLE_FEATURE_TUN_PERSIST

/* TUNSETGROUP appeared in 2.6.23 */
#ifndef TUNSETGROUP
#define TUNSETGROUP   _IOW('T', 206, int)
#endif

void
tuncfg(const char *dev, const char *dev_type, const char *dev_node,
       int persist_mode, const char *username, const char *groupname,
       const struct tuntap_options *options, openvpn_net_ctx_t *ctx)
{
    struct tuntap *tt;

    ALLOC_OBJ(tt, struct tuntap);
    clear_tuntap(tt);
    tt->type = dev_type_enum(dev, dev_type);
    tt->options = *options;

    open_tun(dev, dev_type, dev_node, tt, ctx);
    if (ioctl(tt->fd, TUNSETPERSIST, persist_mode) < 0)
    {
        msg(M_ERR, "Cannot ioctl TUNSETPERSIST(%d) %s", persist_mode, dev);
    }
    if (username != NULL)
    {
        struct platform_state_user platform_state_user;

        if (!platform_user_get(username, &platform_state_user))
        {
            msg(M_ERR, "Cannot get user entry for %s", username);
        }
        else if (ioctl(tt->fd, TUNSETOWNER, platform_state_user.uid) < 0)
        {
            msg(M_ERR, "Cannot ioctl TUNSETOWNER(%s) %s", username, dev);
        }
    }
    if (groupname != NULL)
    {
        struct platform_state_group platform_state_group;

        if (!platform_group_get(groupname, &platform_state_group))
        {
            msg(M_ERR, "Cannot get group entry for %s", groupname);
        }
        else if (ioctl(tt->fd, TUNSETGROUP, platform_state_group.gid) < 0)
        {
            msg(M_ERR, "Cannot ioctl TUNSETGROUP(%s) %s", groupname, dev);
        }
    }
    close_tun(tt, ctx);
    msg(M_INFO, "Persist state set to: %s", (persist_mode ? "ON" : "OFF"));
}

#endif /* ENABLE_FEATURE_TUN_PERSIST */

void
close_tun(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    ASSERT(tt);

#if defined(TARGET_LINUX) || defined(TARGET_FREEBSD)
    if (tun_dco_enabled(tt))
    {
        close_tun_dco(tt, ctx);
    }
#endif
    close_tun_generic(tt);
    free(tt);
}

int
write_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    return write(tt->fd, buf, len);
}

int
read_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    return read(tt->fd, buf, len);
}

#elif defined(TARGET_SOLARIS)

#ifndef TUNNEWPPA
#error I need the symbol TUNNEWPPA from net/if_tun.h
#endif

void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
    int if_fd, ip_muxid, arp_muxid, arp_fd, ppa = -1;
    struct lifreq ifr;
    const char *ptr;
    const char *ip_node, *arp_node;
    const char *dev_tuntap_type;
    int link_type;
    bool is_tun;
    struct strioctl strioc_if, strioc_ppa;

    /* improved generic TUN/TAP driver from
     * http://www.whiteboard.ne.jp/~admin2/tuntap/
     * has IPv6 support
     */
    CLEAR(ifr);

    if (tt->type == DEV_TYPE_NULL)
    {
        open_null(tt);
        return;
    }

    if (tt->type == DEV_TYPE_TUN)
    {
        ip_node = "/dev/udp";
        if (!dev_node)
        {
            dev_node = "/dev/tun";
        }
        dev_tuntap_type = "tun";
        link_type = I_PLINK;
        is_tun = true;
    }
    else if (tt->type == DEV_TYPE_TAP)
    {
        ip_node = "/dev/udp";
        if (!dev_node)
        {
            dev_node = "/dev/tap";
        }
        arp_node = dev_node;
        dev_tuntap_type = "tap";
        link_type = I_PLINK; /* was: I_LINK */
        is_tun = false;
    }
    else
    {
        msg(M_FATAL, "I don't recognize device %s as a tun or tap device",
            dev);
    }

    if ((tt->ip_fd = open(ip_node, O_RDWR, 0)) < 0)
    {
        msg(M_ERR, "Can't open %s", ip_node);
    }

    if ((tt->fd = open(dev_node, O_RDWR, 0)) < 0)
    {
        msg(M_ERR, "Can't open %s", dev_node);
    }

    ptr = dev;

    /* get unit number */
    if (*ptr)
    {
        while (*ptr && !isdigit((int) *ptr))
        {
            ptr++;
        }
        ppa = atoi(ptr);
    }

    /* Assign a new PPA and get its unit number. */
    strioc_ppa.ic_cmd = TUNNEWPPA;
    strioc_ppa.ic_timout = 0;
    strioc_ppa.ic_len = sizeof(ppa);
    strioc_ppa.ic_dp = (char *)&ppa;

    if (*ptr == '\0')           /* no number given, try dynamic */
    {
        bool found_one = false;
        while (!found_one && ppa < 64)
        {
            int new_ppa = ioctl(tt->fd, I_STR, &strioc_ppa);
            if (new_ppa >= 0)
            {
                msg( M_INFO, "open_tun: got dynamic interface '%s%d'", dev_tuntap_type, new_ppa );
                ppa = new_ppa;
                found_one = true;
                break;
            }
            if (errno != EEXIST)
            {
                msg(M_ERR, "open_tun: unexpected error trying to find free %s interface", dev_tuntap_type );
            }
            ppa++;
        }
        if (!found_one)
        {
            msg(M_ERR, "open_tun: could not find free %s interface, give up.", dev_tuntap_type );
        }
    }
    else                        /* try this particular one */
    {
        if ((ppa = ioctl(tt->fd, I_STR, &strioc_ppa)) < 0)
        {
            msg(M_ERR, "Can't assign PPA for new interface (%s%d)", dev_tuntap_type, ppa );
        }
    }

    if ((if_fd = open(dev_node, O_RDWR, 0)) < 0)
    {
        msg(M_ERR, "Can't open %s (2)", dev_node);
    }

    if (ioctl(if_fd, I_PUSH, "ip") < 0)
    {
        msg(M_ERR, "Can't push IP module");
    }

    if (tt->type == DEV_TYPE_TUN)
    {
        /* Assign ppa according to the unit number returned by tun device */
        if (ioctl(if_fd, IF_UNITSEL, (char *) &ppa) < 0)
        {
            msg(M_ERR, "Can't set PPA %d", ppa);
        }
    }

    tt->actual_name = (char *) malloc(32);
    check_malloc_return(tt->actual_name);

    openvpn_snprintf(tt->actual_name, 32, "%s%d", dev_tuntap_type, ppa);

    if (tt->type == DEV_TYPE_TAP)
    {
        if (ioctl(if_fd, SIOCGLIFFLAGS, &ifr) < 0)
        {
            msg(M_ERR, "Can't get flags\n");
        }
        strncpynt(ifr.lifr_name, tt->actual_name, sizeof(ifr.lifr_name));
        ifr.lifr_ppa = ppa;
        /* Assign ppa according to the unit number returned by tun device */
        if (ioctl(if_fd, SIOCSLIFNAME, &ifr) < 0)
        {
            msg(M_ERR, "Can't set PPA %d", ppa);
        }
        if (ioctl(if_fd, SIOCGLIFFLAGS, &ifr) <0)
        {
            msg(M_ERR, "Can't get flags\n");
        }
        /* Push arp module to if_fd */
        if (ioctl(if_fd, I_PUSH, "arp") < 0)
        {
            msg(M_ERR, "Can't push ARP module");
        }

        /* Pop any modules on the stream */
        while (true)
        {
            if (ioctl(tt->ip_fd, I_POP, NULL) < 0)
            {
                break;
            }
        }
        /* Push arp module to ip_fd */
        if (ioctl(tt->ip_fd, I_PUSH, "arp") < 0)
        {
            msg(M_ERR, "Can't push ARP module\n");
        }

        /* Open arp_fd */
        if ((arp_fd = open(arp_node, O_RDWR, 0)) < 0)
        {
            msg(M_ERR, "Can't open %s\n", arp_node);
        }
        /* Push arp module to arp_fd */
        if (ioctl(arp_fd, I_PUSH, "arp") < 0)
        {
            msg(M_ERR, "Can't push ARP module\n");
        }

        /* Set ifname to arp */
        strioc_if.ic_cmd = SIOCSLIFNAME;
        strioc_if.ic_timout = 0;
        strioc_if.ic_len = sizeof(ifr);
        strioc_if.ic_dp = (char *)&ifr;
        if (ioctl(arp_fd, I_STR, &strioc_if) < 0)
        {
            msg(M_ERR, "Can't set ifname to arp\n");
        }
    }

    if ((ip_muxid = ioctl(tt->ip_fd, link_type, if_fd)) < 0)
    {
        msg(M_ERR, "Can't link %s device to IP", dev_tuntap_type);
    }

    if (tt->type == DEV_TYPE_TAP)
    {
        if ((arp_muxid = ioctl(tt->ip_fd, link_type, arp_fd)) < 0)
        {
            msg(M_ERR, "Can't link %s device to ARP", dev_tuntap_type);
        }
        close(arp_fd);
    }

    CLEAR(ifr);
    strncpynt(ifr.lifr_name, tt->actual_name, sizeof(ifr.lifr_name));
    ifr.lifr_ip_muxid  = ip_muxid;
    if (tt->type == DEV_TYPE_TAP)
    {
        ifr.lifr_arp_muxid = arp_muxid;
    }

    if (ioctl(tt->ip_fd, SIOCSLIFMUXID, &ifr) < 0)
    {
        if (tt->type == DEV_TYPE_TAP)
        {
            ioctl(tt->ip_fd, I_PUNLINK, arp_muxid);
        }
        ioctl(tt->ip_fd, I_PUNLINK, ip_muxid);
        msg(M_ERR, "Can't set multiplexor id");
    }

    set_nonblock(tt->fd);
    set_cloexec(tt->fd);
    set_cloexec(tt->ip_fd);

    msg(M_INFO, "TUN/TAP device %s opened", tt->actual_name);
}

static void
solaris_close_tun(struct tuntap *tt)
{
    /* IPv6 interfaces need to be 'manually' de-configured */
    if (tt->did_ifconfig_ipv6_setup)
    {
        struct argv argv = argv_new();
        argv_printf( &argv, "%s %s inet6 unplumb",
                     IFCONFIG_PATH, tt->actual_name );
        argv_msg(M_INFO, &argv);
        openvpn_execve_check(&argv, NULL, 0, "Solaris ifconfig inet6 unplumb failed");
        argv_free(&argv);
    }

    if (tt->ip_fd >= 0)
    {
        struct lifreq ifr;
        CLEAR(ifr);
        strncpynt(ifr.lifr_name, tt->actual_name, sizeof(ifr.lifr_name));

        if (ioctl(tt->ip_fd, SIOCGLIFFLAGS, &ifr) < 0)
        {
            msg(M_WARN | M_ERRNO, "Can't get iface flags");
        }

        if (ioctl(tt->ip_fd, SIOCGLIFMUXID, &ifr) < 0)
        {
            msg(M_WARN | M_ERRNO, "Can't get multiplexor id");
        }

        if (tt->type == DEV_TYPE_TAP)
        {
            if (ioctl(tt->ip_fd, I_PUNLINK, ifr.lifr_arp_muxid) < 0)
            {
                msg(M_WARN | M_ERRNO, "Can't unlink interface(arp)");
            }
        }

        if (ioctl(tt->ip_fd, I_PUNLINK, ifr.lifr_ip_muxid) < 0)
        {
            msg(M_WARN | M_ERRNO, "Can't unlink interface(ip)");
        }

        close(tt->ip_fd);
        tt->ip_fd = -1;
    }

    if (tt->fd >= 0)
    {
        close(tt->fd);
        tt->fd = -1;
    }
}

/*
 * Close TUN device.
 */
void
close_tun(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    ASSERT(tt);

    solaris_close_tun(tt);

    free(tt->actual_name);

    clear_tuntap(tt);
    free(tt);
}

static void
solaris_error_close(struct tuntap *tt, const struct env_set *es,
                    const char *actual, bool unplumb_inet6 )
{
    struct argv argv = argv_new();

    if (unplumb_inet6)
    {
        argv_printf( &argv, "%s %s inet6 unplumb",
                     IFCONFIG_PATH, actual );
        argv_msg(M_INFO, &argv);
        openvpn_execve_check(&argv, es, 0, "Solaris ifconfig inet6 unplumb failed");
    }

    argv_printf(&argv,
                "%s %s unplumb",
                IFCONFIG_PATH,
                actual);

    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, es, 0, "Solaris ifconfig unplumb failed");
    close_tun(tt, NULL);
    msg(M_FATAL, "Solaris ifconfig failed");
    argv_free(&argv);
}

int
write_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    struct strbuf sbuf;
    sbuf.len = len;
    sbuf.buf = (char *)buf;
    return putmsg(tt->fd, NULL, &sbuf, 0) >= 0 ? sbuf.len : -1;
}

int
read_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    struct strbuf sbuf;
    int f = 0;

    sbuf.maxlen = len;
    sbuf.buf = (char *)buf;
    return getmsg(tt->fd, NULL, &sbuf, &f) >= 0 ? sbuf.len : -1;
}

#elif defined(TARGET_OPENBSD)

void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
    open_tun_generic(dev, dev_type, dev_node, tt);

    /* Enable multicast on the interface */
    if (tt->fd >= 0)
    {
        struct tuninfo info;

        if (ioctl(tt->fd, TUNGIFINFO, &info) < 0)
        {
            msg(M_WARN | M_ERRNO, "Can't get interface info");
        }

#ifdef IFF_MULTICAST /* openbsd 4.x doesn't have this */
        info.flags |= IFF_MULTICAST;
#endif

        if (ioctl(tt->fd, TUNSIFINFO, &info) < 0)
        {
            msg(M_WARN | M_ERRNO, "Can't set interface info");
        }
    }
}

/* tun(4): "If the device was created by opening /dev/tunN, it will be
 *          automatically destroyed.  Devices created via ifconfig(8) are
 *          only marked as not running and traffic will be dropped
 *          returning EHOSTDOWN."
 * --> no special handling should be needed - *but* OpenBSD is misbehaving
 * here: if the interface was put in tap mode ("ifconfig tunN link0"), it
 * *will* stay around, and needs to be cleaned up manually
 */

void
close_tun(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    ASSERT(tt);

    /* only *TAP* devices need destroying, tun devices auto-self-destruct
     */
    if (tt->type == DEV_TYPE_TUN || tt->persistent_if)
    {
        close_tun_generic(tt);
        free(tt);
        return;
    }

    struct argv argv = argv_new();

    /* setup command, close tun dev (clears tt->actual_name!), run command
     */

    argv_printf(&argv, "%s %s destroy",
                IFCONFIG_PATH, tt->actual_name);

    close_tun_generic(tt);

    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, NULL, 0, "OpenBSD 'destroy tun interface' failed (non-critical)");

    free(tt);
    argv_free(&argv);
}

int
write_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    return write_tun_header(tt, buf, len);
}

int
read_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    return read_tun_header(tt, buf, len);
}

#elif defined(TARGET_NETBSD)

/*
 * NetBSD 4.0 and up support IPv6 on tun interfaces, but we need to put
 * the tun interface into "multi_af" mode, which will prepend the address
 * family to all packets (same as OpenBSD and FreeBSD).
 *
 * If this is not enabled, the kernel silently drops all IPv6 packets on
 * output and gets confused on input.
 *
 * Note: --dev tap3 works *if* the interface is created externally by
 *         "ifconfig tap3 create"
 *         (and for devices beyond tap3, "mknod /dev/tapN c ...")
 *       but we do not have code to do that inside OpenVPN
 */

void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
    /* on NetBSD, tap (but not tun) devices are opened by
     * opening /dev/tap and then querying the system about the
     * actual device name (tap0, tap1, ...) assigned
     */
    if (strcmp(dev, "tap") == 0)
    {
        struct ifreq ifr;
        if ((tt->fd = open( "/dev/tap", O_RDWR)) < 0)
        {
            msg(M_FATAL, "Cannot allocate NetBSD TAP dev dynamically");
        }
        if (ioctl( tt->fd, TAPGIFNAME, (void *)&ifr ) < 0)
        {
            msg(M_FATAL, "Cannot query NetBSD TAP device name");
        }
        set_nonblock(tt->fd);
        set_cloexec(tt->fd); /* don't pass fd to scripts */
        msg(M_INFO, "TUN/TAP device %s opened", ifr.ifr_name);

        tt->actual_name = string_alloc(ifr.ifr_name, NULL);
    }
    else
    {
        /* dynamic / named tun can be handled by the generic function
         * named tap ("tap3") is handled there as well, if pre-created
         */
        open_tun_generic(dev, dev_type, dev_node, tt);
    }

    if (tt->fd >= 0)
    {
        int i = IFF_POINTOPOINT|IFF_MULTICAST;
        ioctl(tt->fd, TUNSIFMODE, &i);   /* multicast on */
        i = 0;
        ioctl(tt->fd, TUNSLMODE, &i);    /* link layer mode off */

        if (tt->type == DEV_TYPE_TUN)
        {
            i = 1;
            if (ioctl(tt->fd, TUNSIFHEAD, &i) < 0)      /* multi-af mode on */
            {
                msg(M_WARN | M_ERRNO, "ioctl(TUNSIFHEAD)");
            }
        }
    }
}

/* the current way OpenVPN handles tun devices on NetBSD leads to
 * lingering tunX interfaces after close -> for a full cleanup, they
 * need to be explicitly destroyed
 */
void
close_tun(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    ASSERT(tt);

    /* only tun devices need destroying, tap devices auto-self-destruct
     */
    if (tt->type != DEV_TYPE_TUN || tt->persistent_if)
    {
        close_tun_generic(tt);
        free(tt);
        return;
    }

    struct argv argv = argv_new();

    /* setup command, close tun dev (clears tt->actual_name!), run command
     */

    argv_printf(&argv, "%s %s destroy",
                IFCONFIG_PATH, tt->actual_name);

    close_tun_generic(tt);

    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, NULL, 0, "NetBSD 'destroy tun interface' failed (non-critical)");

    free(tt);
    argv_free(&argv);
}

static inline int
netbsd_modify_read_write_return(int len)
{
    if (len > 0)
    {
        return len > sizeof(u_int32_t) ? len - sizeof(u_int32_t) : 0;
    }
    else
    {
        return len;
    }
}

int
write_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    if (tt->type == DEV_TYPE_TUN)
    {
        u_int32_t type;
        struct iovec iv[2];
        struct openvpn_iphdr *iph;

        iph = (struct openvpn_iphdr *) buf;

        if (OPENVPN_IPH_GET_VER(iph->version_len) == 6)
        {
            type = htonl(AF_INET6);
        }
        else
        {
            type = htonl(AF_INET);
        }

        iv[0].iov_base = (char *)&type;
        iv[0].iov_len = sizeof(type);
        iv[1].iov_base = buf;
        iv[1].iov_len = len;

        return netbsd_modify_read_write_return(writev(tt->fd, iv, 2));
    }
    else
    {
        return write(tt->fd, buf, len);
    }
}

int
read_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    if (tt->type == DEV_TYPE_TUN)
    {
        u_int32_t type;
        struct iovec iv[2];

        iv[0].iov_base = (char *)&type;
        iv[0].iov_len = sizeof(type);
        iv[1].iov_base = buf;
        iv[1].iov_len = len;

        return netbsd_modify_read_write_return(readv(tt->fd, iv, 2));
    }
    else
    {
        return read(tt->fd, buf, len);
    }
}

#elif defined(TARGET_FREEBSD)

static inline int
freebsd_modify_read_write_return(int len)
{
    if (len > 0)
    {
        return len > sizeof(u_int32_t) ? len - sizeof(u_int32_t) : 0;
    }
    else
    {
        return len;
    }
}

void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
    if (tun_dco_enabled(tt))
    {
        open_tun_dco_generic(dev, dev_type, tt, ctx);
    }
    else
    {
        open_tun_generic(dev, dev_type, dev_node, tt);

        if (tt->fd >= 0 && tt->type == DEV_TYPE_TUN)
        {
            /* see "Interface Flags" in ifnet(9) */
            int i = IFF_POINTOPOINT | IFF_MULTICAST;
            if (tt->topology == TOP_SUBNET)
            {
                i = IFF_BROADCAST | IFF_MULTICAST;
            }

            if (ioctl(tt->fd, TUNSIFMODE, &i) < 0)
            {
                msg(M_WARN | M_ERRNO, "ioctl(TUNSIFMODE)");
            }

            /* multi_af mode for v4+v6, see "tun(4)" */
            i = 1;
            if (ioctl(tt->fd, TUNSIFHEAD, &i) < 0)
            {
                msg(M_WARN | M_ERRNO, "ioctl(TUNSIFHEAD)");
            }
        }
    }
}

/* tun(4): "These network interfaces persist until the if_tun.ko module is
 *          unloaded, or until removed with the ifconfig(8) command."
 *          (verified for FreeBSD 6.3, 7.4, 8.2 and 9, same for tap(4))
 *
 * so, to avoid lingering tun/tap interfaces after OpenVPN quits,
 * we need to call "ifconfig ... destroy" for cleanup
 */
void
close_tun(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    ASSERT(tt);

    if (tt->persistent_if)        /* keep pre-existing if around */
    {
        close_tun_generic(tt);
        free(tt);
        return;
    }

    /* close and destroy */
    struct argv argv = argv_new();

    /* setup command, close tun dev (clears tt->actual_name!), run command
     */

    argv_printf(&argv, "%s %s destroy",
                IFCONFIG_PATH, tt->actual_name);

    close_tun_generic(tt);

    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, NULL, 0,
                         "FreeBSD 'destroy tun interface' failed (non-critical)");

    free(tt);
    argv_free(&argv);
}

int
write_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    if (tt->type == DEV_TYPE_TUN)
    {
        u_int32_t type;
        struct iovec iv[2];
        struct ip *iph;

        iph = (struct ip *) buf;

        if (iph->ip_v == 6)
        {
            type = htonl(AF_INET6);
        }
        else
        {
            type = htonl(AF_INET);
        }

        iv[0].iov_base = (char *)&type;
        iv[0].iov_len = sizeof(type);
        iv[1].iov_base = buf;
        iv[1].iov_len = len;

        return freebsd_modify_read_write_return(writev(tt->fd, iv, 2));
    }
    else
    {
        return write(tt->fd, buf, len);
    }
}

int
read_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    if (tt->type == DEV_TYPE_TUN)
    {
        u_int32_t type;
        struct iovec iv[2];

        iv[0].iov_base = (char *)&type;
        iv[0].iov_len = sizeof(type);
        iv[1].iov_base = buf;
        iv[1].iov_len = len;

        return freebsd_modify_read_write_return(readv(tt->fd, iv, 2));
    }
    else
    {
        return read(tt->fd, buf, len);
    }
}

#elif defined(TARGET_DRAGONFLY)

static inline int
dragonfly_modify_read_write_return(int len)
{
    if (len > 0)
    {
        return len > sizeof(u_int32_t) ? len - sizeof(u_int32_t) : 0;
    }
    else
    {
        return len;
    }
}

void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
    open_tun_generic(dev, dev_type, dev_node, tt);

    if (tt->fd >= 0)
    {
        int i = 0;

        /* Disable extended modes */
        ioctl(tt->fd, TUNSLMODE, &i);
        i = 1;
        ioctl(tt->fd, TUNSIFHEAD, &i);
    }
}

void
close_tun(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    ASSERT(tt);

    close_tun_generic(tt);
    free(tt);
}

int
write_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    if (tt->type == DEV_TYPE_TUN)
    {
        u_int32_t type;
        struct iovec iv[2];
        struct ip *iph;

        iph = (struct ip *) buf;

        if (iph->ip_v == 6)
        {
            type = htonl(AF_INET6);
        }
        else
        {
            type = htonl(AF_INET);
        }

        iv[0].iov_base = (char *)&type;
        iv[0].iov_len = sizeof(type);
        iv[1].iov_base = buf;
        iv[1].iov_len = len;

        return dragonfly_modify_read_write_return(writev(tt->fd, iv, 2));
    }
    else
    {
        return write(tt->fd, buf, len);
    }
}

int
read_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    if (tt->type == DEV_TYPE_TUN)
    {
        u_int32_t type;
        struct iovec iv[2];

        iv[0].iov_base = (char *)&type;
        iv[0].iov_len = sizeof(type);
        iv[1].iov_base = buf;
        iv[1].iov_len = len;

        return dragonfly_modify_read_write_return(readv(tt->fd, iv, 2));
    }
    else
    {
        return read(tt->fd, buf, len);
    }
}

#elif defined(TARGET_DARWIN)

/* Darwin (MacOS X) is mostly "just use the generic stuff", but there
 * is always one caveat...:
 *
 * If IPv6 is configured, and the tun device is closed, the IPv6 address
 * configured to the tun interface changes to a lingering /128 route
 * pointing to lo0.  Need to unconfigure...  (observed on 10.5)
 */

/*
 * utun is the native Darwin tun driver present since at least 10.7
 * Thanks goes to Jonathan Levin for providing an example how to utun
 * (http://newosxbook.com/src.jl?tree=listings&file=17-15-utun.c)
 */

#ifdef HAVE_NET_IF_UTUN_H

/* Helper functions that tries to open utun device
 * return -2 on early initialization failures (utun not supported
 * at all (old OS X) and -1 on initlization failure of utun
 * device (utun works but utunX is already used */
static
int
utun_open_helper(struct ctl_info ctlInfo, int utunnum)
{
    struct sockaddr_ctl sc;
    int fd;

    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

    if (fd < 0)
    {
        msg(M_INFO | M_ERRNO, "Opening utun%d failed (socket(SYSPROTO_CONTROL))",
            utunnum);
        return -2;
    }

    if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1)
    {
        close(fd);
        msg(M_INFO | M_ERRNO, "Opening utun%d failed (ioctl(CTLIOCGINFO))",
            utunnum);
        return -2;
    }


    sc.sc_id = ctlInfo.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;

    sc.sc_unit = utunnum+1;


    /* If the connect is successful, a utun%d device will be created, where "%d"
     * is (sc.sc_unit - 1) */

    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0)
    {
        msg(M_INFO | M_ERRNO, "Opening utun%d failed (connect(AF_SYS_CONTROL))",
            utunnum);
        close(fd);
        return -1;
    }

    set_nonblock(fd);
    set_cloexec(fd); /* don't pass fd to scripts */

    return fd;
}

void
open_darwin_utun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
    struct ctl_info ctlInfo;
    int fd;
    char utunname[20];
    int utunnum = -1;
    socklen_t utunname_len = sizeof(utunname);

    /* dev_node is simply utun, do the normal dynamic utun
     * otherwise try to parse the utun number */
    if (dev_node && (strcmp("utun", dev_node) != 0 ))
    {
        if (sscanf(dev_node, "utun%d", &utunnum) != 1)
        {
            msg(M_FATAL, "Cannot parse 'dev-node %s' please use 'dev-node utunX'"
                "to use a utun device number X", dev_node);
        }
    }



    CLEAR(ctlInfo);
    if (strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name)) >=
        sizeof(ctlInfo.ctl_name))
    {
        msg(M_ERR, "Opening utun: UTUN_CONTROL_NAME too long");
    }

    /* try to open first available utun device if no specific utun is requested */
    if (utunnum == -1)
    {
        for (utunnum = 0; utunnum < 255; utunnum++)
        {
            char ifname[20];
            /* if the interface exists silently skip it */
            ASSERT(snprintf(ifname, sizeof(ifname), "utun%d", utunnum) > 0);
            if (if_nametoindex(ifname))
            {
                continue;
            }
            fd = utun_open_helper(ctlInfo, utunnum);
            /* Break if the fd is valid,
             * or if early initialization failed (-2) */
            if (fd !=-1)
            {
                break;
            }
        }
    }
    else
    {
        fd = utun_open_helper(ctlInfo, utunnum);
    }

    /* opening an utun device failed */
    tt->fd = fd;

    if (fd < 0)
    {
        return;
    }

    /* Retrieve the assigned interface name. */
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, utunname, &utunname_len))
    {
        msg(M_ERR | M_ERRNO, "Error retrieving utun interface name");
    }

    tt->actual_name = string_alloc(utunname, NULL);

    msg(M_INFO, "Opened utun device %s", utunname);
    tt->is_utun = true;
}

#endif /* ifdef HAVE_NET_IF_UTUN_H */

void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
#ifdef HAVE_NET_IF_UTUN_H
    /* If dev_node does not start start with utun assume regular tun/tap */
    if ((!dev_node && tt->type==DEV_TYPE_TUN)
        || (dev_node && !strncmp(dev_node, "utun", 4)))
    {

        /* Check if user has specific dev_type tap and forced utun with
         * dev-node utun */
        if (tt->type!=DEV_TYPE_TUN)
        {
            msg(M_FATAL, "Cannot use utun devices with --dev-type %s",
                dev_type_string(dev, dev_type));
        }

        /* Try utun first and fall back to normal tun if utun fails
         * and dev_node is not specified */
        open_darwin_utun(dev, dev_type, dev_node, tt);

        if (!tt->is_utun)
        {
            if (!dev_node)
            {
                /* No explicit utun and utun failed, try the generic way) */
                msg(M_INFO, "Failed to open utun device. Falling back to /dev/tun device");
                open_tun_generic(dev, dev_type, NULL, tt);
            }
            else
            {
                /* Specific utun device or generic utun request with no tun
                 * fall back failed, consider this a fatal failure */
                msg(M_FATAL, "Cannot open utun device");
            }
        }
    }
    else
#endif /* ifdef HAVE_NET_IF_UTUN_H */
    {

        /* Use plain dev-node tun to select /dev/tun style
         * Unset dev_node variable prior to passing to open_tun_generic to
         * let open_tun_generic pick the first available tun device */

        if (dev_node && strcmp(dev_node, "tun")==0)
        {
            dev_node = NULL;
        }

        open_tun_generic(dev, dev_type, dev_node, tt);
    }
}

void
close_tun(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    ASSERT(tt);

    struct gc_arena gc = gc_new();
    struct argv argv = argv_new();

    if (tt->did_ifconfig_ipv6_setup)
    {
        const char *ifconfig_ipv6_local =
            print_in6_addr(tt->local_ipv6, 0, &gc);

        argv_printf(&argv, "%s delete -inet6 %s",
                    ROUTE_PATH, ifconfig_ipv6_local );
        argv_msg(M_INFO, &argv);
        openvpn_execve_check(&argv, NULL, 0, "MacOS X 'remove inet6 route' failed (non-critical)");
    }

    close_tun_generic(tt);
    free(tt);
    argv_free(&argv);
    gc_free(&gc);
}

int
write_tun(struct tuntap *tt, uint8_t *buf, int len)
{
#ifdef HAVE_NET_IF_UTUN_H
    if (tt->is_utun)
    {
        return write_tun_header(tt, buf, len);
    }
    else
#endif
    return write(tt->fd, buf, len);
}

int
read_tun(struct tuntap *tt, uint8_t *buf, int len)
{
#ifdef HAVE_NET_IF_UTUN_H
    if (tt->is_utun)
    {
        return read_tun_header(tt, buf, len);
    }
    else
#endif
    return read(tt->fd, buf, len);
}

#elif defined(TARGET_AIX)

void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
    char tunname[256];
    char dynamic_name[20];
    const char *p;

    if (tt->type == DEV_TYPE_NULL)
    {
        open_null(tt);
        return;
    }

    if (tt->type == DEV_TYPE_TUN)
    {
        msg(M_FATAL, "no support for 'tun' devices on AIX" );
    }

    if (strncmp( dev, "tap", 3 ) != 0 || dev_node)
    {
        msg(M_FATAL, "'--dev %s' and/or '--dev-node' not supported on AIX, use '--dev tap0', 'tap1', etc.", dev );
    }

    if (strcmp( dev, "tap" ) == 0)              /* find first free tap dev */
    {                                           /* (= no /dev/tapN node) */
        int i;
        for (i = 0; i<99; i++)
        {
            openvpn_snprintf(tunname, sizeof(tunname), "/dev/tap%d", i);
            if (access( tunname, F_OK ) < 0 && errno == ENOENT)
            {
                break;
            }
        }
        if (i >= 99)
        {
            msg( M_FATAL, "cannot find unused tap device" );
        }

        openvpn_snprintf( dynamic_name, sizeof(dynamic_name), "tap%d", i );
        dev = dynamic_name;
    }
    else                                        /* name given, sanity check */
    {
        /* ensure that dev name is "tap+<digits>" *only* */
        p = &dev[3];
        while (isdigit(*p) )
        {
            p++;
        }
        if (*p != '\0')
        {
            msg( M_FATAL, "TAP device name must be '--dev tapNNNN'" );
        }

        openvpn_snprintf(tunname, sizeof(tunname), "/dev/%s", dev);
    }

    /* pre-existing device?
     */
    if (access( tunname, F_OK ) < 0 && errno == ENOENT)
    {

        /* tunnel device must be created with 'ifconfig tapN create'
         */
        struct argv argv = argv_new();
        struct env_set *es = env_set_create(NULL);
        argv_printf(&argv, "%s %s create", IFCONFIG_PATH, dev);
        argv_msg(M_INFO, &argv);
        env_set_add( es, "ODMDIR=/etc/objrepos" );
        openvpn_execve_check(&argv, es, S_FATAL, "AIX 'create tun interface' failed");
        env_set_destroy(es);
        argv_free(&argv);
    }
    else
    {
        /* we didn't make it, we're not going to break it */
        tt->persistent_if = TRUE;
    }

    if ((tt->fd = open(tunname, O_RDWR)) < 0)
    {
        msg(M_ERR, "Cannot open TAP device '%s'", tunname);
    }

    set_nonblock(tt->fd);
    set_cloexec(tt->fd); /* don't pass fd to scripts */
    msg(M_INFO, "TUN/TAP device %s opened", tunname);

    /* tt->actual_name is passed to up and down scripts and used as the ifconfig dev name */
    tt->actual_name = string_alloc(dev, NULL);
}

/* tap devices need to be manually destroyed on AIX
 */
void
close_tun(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    ASSERT(tt);

    struct argv argv = argv_new();
    struct env_set *es = env_set_create(NULL);

    /* persistent devices need IP address unconfig, others need destroyal
     */
    if (tt->persistent_if)
    {
        argv_printf(&argv, "%s %s 0.0.0.0 down",
                    IFCONFIG_PATH, tt->actual_name);
    }
    else
    {
        argv_printf(&argv, "%s %s destroy",
                    IFCONFIG_PATH, tt->actual_name);
    }

    close_tun_generic(tt);
    argv_msg(M_INFO, &argv);
    env_set_add( es, "ODMDIR=/etc/objrepos" );
    openvpn_execve_check(&argv, es, 0, "AIX 'destroy tap interface' failed (non-critical)");

    free(tt);
    env_set_destroy(es);
    argv_free(&argv);
}

int
write_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    return write(tt->fd, buf, len);
}

int
read_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    return read(tt->fd, buf, len);
}

#elif defined(_WIN32)

int
tun_read_queue(struct tuntap *tt, int maxsize)
{
    if (tt->reads.iostate == IOSTATE_INITIAL)
    {
        DWORD len;
        BOOL status;
        int err;

        /* reset buf to its initial state */
        tt->reads.buf = tt->reads.buf_init;

        len = maxsize ? maxsize : BLEN(&tt->reads.buf);
        ASSERT(len <= BLEN(&tt->reads.buf));

        /* the overlapped read will signal this event on I/O completion */
        ASSERT(ResetEvent(tt->reads.overlapped.hEvent));

        status = ReadFile(
            tt->hand,
            BPTR(&tt->reads.buf),
            len,
            &tt->reads.size,
            &tt->reads.overlapped
            );

        if (status) /* operation completed immediately? */
        {
            /* since we got an immediate return, we must signal the event object ourselves */
            ASSERT(SetEvent(tt->reads.overlapped.hEvent));

            tt->reads.iostate = IOSTATE_IMMEDIATE_RETURN;
            tt->reads.status = 0;

            dmsg(D_WIN32_IO, "WIN32 I/O: TAP Read immediate return [%d,%d]",
                 (int) len,
                 (int) tt->reads.size);
        }
        else
        {
            err = GetLastError();
            if (err == ERROR_IO_PENDING) /* operation queued? */
            {
                tt->reads.iostate = IOSTATE_QUEUED;
                tt->reads.status = err;
                dmsg(D_WIN32_IO, "WIN32 I/O: TAP Read queued [%d]",
                     (int) len);
            }
            else /* error occurred */
            {
                struct gc_arena gc = gc_new();
                ASSERT(SetEvent(tt->reads.overlapped.hEvent));
                tt->reads.iostate = IOSTATE_IMMEDIATE_RETURN;
                tt->reads.status = err;
                dmsg(D_WIN32_IO, "WIN32 I/O: TAP Read error [%d] : %s",
                     (int) len,
                     strerror_win32(status, &gc));
                gc_free(&gc);
            }
        }
    }
    return tt->reads.iostate;
}

int
tun_write_queue(struct tuntap *tt, struct buffer *buf)
{
    if (tt->writes.iostate == IOSTATE_INITIAL)
    {
        BOOL status;
        int err;

        /* make a private copy of buf */
        tt->writes.buf = tt->writes.buf_init;
        tt->writes.buf.len = 0;
        ASSERT(buf_copy(&tt->writes.buf, buf));

        /* the overlapped write will signal this event on I/O completion */
        ASSERT(ResetEvent(tt->writes.overlapped.hEvent));

        status = WriteFile(
            tt->hand,
            BPTR(&tt->writes.buf),
            BLEN(&tt->writes.buf),
            &tt->writes.size,
            &tt->writes.overlapped
            );

        if (status) /* operation completed immediately? */
        {
            tt->writes.iostate = IOSTATE_IMMEDIATE_RETURN;

            /* since we got an immediate return, we must signal the event object ourselves */
            ASSERT(SetEvent(tt->writes.overlapped.hEvent));

            tt->writes.status = 0;

            dmsg(D_WIN32_IO, "WIN32 I/O: TAP Write immediate return [%d,%d]",
                 BLEN(&tt->writes.buf),
                 (int) tt->writes.size);
        }
        else
        {
            err = GetLastError();
            if (err == ERROR_IO_PENDING) /* operation queued? */
            {
                tt->writes.iostate = IOSTATE_QUEUED;
                tt->writes.status = err;
                dmsg(D_WIN32_IO, "WIN32 I/O: TAP Write queued [%d]",
                     BLEN(&tt->writes.buf));
            }
            else /* error occurred */
            {
                struct gc_arena gc = gc_new();
                ASSERT(SetEvent(tt->writes.overlapped.hEvent));
                tt->writes.iostate = IOSTATE_IMMEDIATE_RETURN;
                tt->writes.status = err;
                dmsg(D_WIN32_IO, "WIN32 I/O: TAP Write error [%d] : %s",
                     BLEN(&tt->writes.buf),
                     strerror_win32(err, &gc));
                gc_free(&gc);
            }
        }
    }
    return tt->writes.iostate;
}

int
tun_write_win32(struct tuntap *tt, struct buffer *buf)
{
    int err = 0;
    int status = 0;
    if (overlapped_io_active(&tt->writes))
    {
        sockethandle_t sh = { .is_handle = true, .h = tt->hand };
        status = sockethandle_finalize(sh, &tt->writes, NULL, NULL);
        if (status < 0)
        {
            err = GetLastError();
        }
    }
    tun_write_queue(tt, buf);
    if (status < 0)
    {
        SetLastError(err);
        return status;
    }
    else
    {
        return BLEN(buf);
    }
}

static const struct device_instance_id_interface *
get_device_instance_id_interface(struct gc_arena *gc)
{
    HDEVINFO dev_info_set;
    DWORD err;
    struct device_instance_id_interface *first = NULL;
    struct device_instance_id_interface *last = NULL;

    dev_info_set = SetupDiGetClassDevsEx(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (dev_info_set == INVALID_HANDLE_VALUE)
    {
        err = GetLastError();
        msg(M_FATAL, "Error [%u] opening device information set key: %s", (unsigned int)err, strerror_win32(err, gc));
    }

    msg(D_TAP_WIN_DEBUG, "Enumerate device interface lists:");
    for (DWORD i = 0;; ++i)
    {
        SP_DEVINFO_DATA device_info_data;
        BOOL res;
        HKEY dev_key;
        char net_cfg_instance_id_string[] = "NetCfgInstanceId";
        BYTE net_cfg_instance_id[256];
        char device_instance_id[256];
        DWORD len;
        DWORD data_type;
        LONG status;
        ULONG dev_interface_list_size;
        CONFIGRET cr;

        ZeroMemory(&device_info_data, sizeof(SP_DEVINFO_DATA));
        device_info_data.cbSize = sizeof(SP_DEVINFO_DATA);
        res = SetupDiEnumDeviceInfo(dev_info_set, i, &device_info_data);
        if (!res)
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            else
            {
                continue;
            }
        }

        dev_key = SetupDiOpenDevRegKey(dev_info_set, &device_info_data, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
        if (dev_key == INVALID_HANDLE_VALUE)
        {
            continue;
        }

        len = sizeof(net_cfg_instance_id);
        data_type = REG_SZ;
        status = RegQueryValueEx(dev_key,
                                 net_cfg_instance_id_string,
                                 NULL,
                                 &data_type,
                                 net_cfg_instance_id,
                                 &len);
        if (status != ERROR_SUCCESS)
        {
            goto next;
        }

        len = sizeof(device_instance_id);
        res = SetupDiGetDeviceInstanceId(dev_info_set, &device_info_data, device_instance_id, len, &len);
        if (!res)
        {
            goto next;
        }

        cr = CM_Get_Device_Interface_List_Size(&dev_interface_list_size,
                                               (LPGUID)&GUID_DEVINTERFACE_NET,
                                               device_instance_id,
                                               CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

        if (cr != CR_SUCCESS)
        {
            goto next;
        }

        char *dev_interface_list = gc_malloc(dev_interface_list_size, false, gc);
        cr = CM_Get_Device_Interface_List((LPGUID)&GUID_DEVINTERFACE_NET, device_instance_id,
                                          dev_interface_list,
                                          dev_interface_list_size,
                                          CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
        if (cr != CR_SUCCESS)
        {
            goto next;
        }

        char *dev_if = dev_interface_list;

        /* device interface list ends with empty string */
        while (strlen(dev_if) > 0)
        {
            struct device_instance_id_interface *dev_iif;
            ALLOC_OBJ_CLEAR_GC(dev_iif, struct device_instance_id_interface, gc);
            dev_iif->net_cfg_instance_id = (unsigned char *)string_alloc((char *)net_cfg_instance_id, gc);
            dev_iif->device_interface = string_alloc(dev_if, gc);

            msg(D_TAP_WIN_DEBUG, "NetCfgInstanceId: %s, Device Interface: %s",
                dev_iif->net_cfg_instance_id,
                dev_iif->device_interface);

            /* link into return list */
            if (!first)
            {
                first = dev_iif;
            }
            if (last)
            {
                last->next = dev_iif;
            }
            last = dev_iif;

            dev_if += strlen(dev_if) + 1;
        }

next:
        RegCloseKey(dev_key);
    }

    SetupDiDestroyDeviceInfoList(dev_info_set);

    return first;
}

static const struct tap_reg *
get_tap_reg(struct gc_arena *gc)
{
    HKEY adapter_key;
    LONG status;
    DWORD len;
    struct tap_reg *first = NULL;
    struct tap_reg *last = NULL;
    int i = 0;

    status = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        ADAPTER_KEY,
        0,
        KEY_READ,
        &adapter_key);

    if (status != ERROR_SUCCESS)
    {
        msg(M_FATAL, "Error opening registry key: %s", ADAPTER_KEY);
    }

    msg(D_TAP_WIN_DEBUG, "Enumerate drivers in registy: ");
    while (true)
    {
        char enum_name[256];
        char unit_string[256];
        HKEY unit_key;
        char component_id_string[] = "ComponentId";
        char component_id[256];
        char net_cfg_instance_id_string[] = "NetCfgInstanceId";
        BYTE net_cfg_instance_id[256];
        DWORD data_type;

        len = sizeof(enum_name);
        status = RegEnumKeyEx(
            adapter_key,
            i,
            enum_name,
            &len,
            NULL,
            NULL,
            NULL,
            NULL);
        if (status == ERROR_NO_MORE_ITEMS)
        {
            break;
        }
        else if (status != ERROR_SUCCESS)
        {
            msg(M_FATAL, "Error enumerating registry subkeys of key: %s",
                ADAPTER_KEY);
        }

        openvpn_snprintf(unit_string, sizeof(unit_string), "%s\\%s",
                         ADAPTER_KEY, enum_name);

        status = RegOpenKeyEx(
            HKEY_LOCAL_MACHINE,
            unit_string,
            0,
            KEY_READ,
            &unit_key);

        if (status != ERROR_SUCCESS)
        {
            dmsg(D_REGISTRY, "Error opening registry key: %s", unit_string);
        }
        else
        {
            len = sizeof(component_id);
            status = RegQueryValueEx(
                unit_key,
                component_id_string,
                NULL,
                &data_type,
                (LPBYTE)component_id,
                &len);

            if (status != ERROR_SUCCESS || data_type != REG_SZ)
            {
                dmsg(D_REGISTRY, "Error opening registry key: %s\\%s",
                     unit_string, component_id_string);
            }
            else
            {
                len = sizeof(net_cfg_instance_id);
                status = RegQueryValueEx(
                    unit_key,
                    net_cfg_instance_id_string,
                    NULL,
                    &data_type,
                    net_cfg_instance_id,
                    &len);

                if (status == ERROR_SUCCESS && data_type == REG_SZ)
                {
                    /* Is this adapter supported? */
                    enum windows_driver_type windows_driver = WINDOWS_DRIVER_UNSPECIFIED;
                    if (strcasecmp(component_id, TAP_WIN_COMPONENT_ID) == 0
                        || strcasecmp(component_id, "root\\" TAP_WIN_COMPONENT_ID) == 0)
                    {
                        windows_driver = WINDOWS_DRIVER_TAP_WINDOWS6;
                    }
                    else if (strcasecmp(component_id, WINTUN_COMPONENT_ID) == 0)
                    {
                        windows_driver = WINDOWS_DRIVER_WINTUN;
                    }
                    else if (strcasecmp(component_id, "ovpn-dco") == 0)
                    {
                        windows_driver = WINDOWS_DRIVER_DCO;
                    }

                    if (windows_driver != WINDOWS_DRIVER_UNSPECIFIED)
                    {
                        struct tap_reg *reg;
                        ALLOC_OBJ_CLEAR_GC(reg, struct tap_reg, gc);
                        reg->guid = string_alloc((char *)net_cfg_instance_id, gc);
                        reg->windows_driver = windows_driver;

                        /* link into return list */
                        if (!first)
                        {
                            first = reg;
                        }
                        if (last)
                        {
                            last->next = reg;
                        }
                        last = reg;

                        msg(D_TAP_WIN_DEBUG, "NetCfgInstanceId: %s, Driver: %s",
                            reg->guid, print_windows_driver(reg->windows_driver));
                    }
                }
            }
            RegCloseKey(unit_key);
        }
        ++i;
    }

    RegCloseKey(adapter_key);
    return first;
}

static const struct panel_reg *
get_panel_reg(struct gc_arena *gc)
{
    LONG status;
    HKEY network_connections_key;
    DWORD len;
    struct panel_reg *first = NULL;
    struct panel_reg *last = NULL;
    int i = 0;

    status = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        NETWORK_CONNECTIONS_KEY,
        0,
        KEY_READ,
        &network_connections_key);

    if (status != ERROR_SUCCESS)
    {
        msg(M_FATAL, "Error opening registry key: %s", NETWORK_CONNECTIONS_KEY);
    }

    while (true)
    {
        char enum_name[256];
        char connection_string[256];
        HKEY connection_key;
        WCHAR name_data[256];
        DWORD name_type;
        const WCHAR name_string[] = L"Name";

        len = sizeof(enum_name);
        status = RegEnumKeyEx(
            network_connections_key,
            i,
            enum_name,
            &len,
            NULL,
            NULL,
            NULL,
            NULL);
        if (status == ERROR_NO_MORE_ITEMS)
        {
            break;
        }
        else if (status != ERROR_SUCCESS)
        {
            msg(M_FATAL, "Error enumerating registry subkeys of key: %s",
                NETWORK_CONNECTIONS_KEY);
        }

        openvpn_snprintf(connection_string, sizeof(connection_string),
                         "%s\\%s\\Connection",
                         NETWORK_CONNECTIONS_KEY, enum_name);

        status = RegOpenKeyEx(
            HKEY_LOCAL_MACHINE,
            connection_string,
            0,
            KEY_READ,
            &connection_key);

        if (status != ERROR_SUCCESS)
        {
            dmsg(D_REGISTRY, "Error opening registry key: %s", connection_string);
        }
        else
        {
            len = sizeof(name_data);
            status = RegQueryValueExW(
                connection_key,
                name_string,
                NULL,
                &name_type,
                (LPBYTE) name_data,
                &len);

            if (status != ERROR_SUCCESS || name_type != REG_SZ)
            {
                dmsg(D_REGISTRY, "Error opening registry key: %s\\%s\\%ls",
                     NETWORK_CONNECTIONS_KEY, connection_string, name_string);
            }
            else
            {
                int n;
                LPSTR name;
                struct panel_reg *reg;

                ALLOC_OBJ_CLEAR_GC(reg, struct panel_reg, gc);
                n = WideCharToMultiByte(CP_UTF8, 0, name_data, -1, NULL, 0, NULL, NULL);
                name = gc_malloc(n, false, gc);
                WideCharToMultiByte(CP_UTF8, 0, name_data, -1, name, n, NULL, NULL);
                reg->name = name;
                reg->guid = string_alloc(enum_name, gc);

                /* link into return list */
                if (!first)
                {
                    first = reg;
                }
                if (last)
                {
                    last->next = reg;
                }
                last = reg;
            }
            RegCloseKey(connection_key);
        }
        ++i;
    }

    RegCloseKey(network_connections_key);

    return first;
}

/*
 * Check that two addresses are part of the same 255.255.255.252 subnet.
 */
void
verify_255_255_255_252(in_addr_t local, in_addr_t remote)
{
    struct gc_arena gc = gc_new();
    const unsigned int mask = 3;
    const char *err = NULL;

    if (local == remote)
    {
        err = "must be different";
        goto error;
    }
    if ((local & (~mask)) != (remote & (~mask)))
    {
        err = "must exist within the same 255.255.255.252 subnet.  This is a limitation of --dev tun when used with the TAP-WIN32 driver";
        goto error;
    }
    if ((local & mask) == 0
        || (local & mask) == 3
        || (remote & mask) == 0
        || (remote & mask) == 3)
    {
        err = "cannot use the first or last address within a given 255.255.255.252 subnet.  This is a limitation of --dev tun when used with the TAP-WIN32 driver";
        goto error;
    }

    gc_free(&gc);
    return;

error:
    msg(M_FATAL, "There is a problem in your selection of --ifconfig endpoints [local=%s, remote=%s].  The local and remote VPN endpoints %s.  Try '" PACKAGE " --show-valid-subnets' option for more info.",
        print_in_addr_t(local, 0, &gc),
        print_in_addr_t(remote, 0, &gc),
        err);
    gc_free(&gc);
}

void
show_valid_win32_tun_subnets(void)
{
    int i;
    int col = 0;

    printf("On Windows, point-to-point IP support (i.e. --dev tun)\n");
    printf("is emulated by the TAP-Windows driver.  The major limitation\n");
    printf("imposed by this approach is that the --ifconfig local and\n");
    printf("remote endpoints must be part of the same 255.255.255.252\n");
    printf("subnet.  The following list shows examples of endpoint\n");
    printf("pairs which satisfy this requirement.  Only the final\n");
    printf("component of the IP address pairs is at issue.\n\n");
    printf("As an example, the following option would be correct:\n");
    printf("    --ifconfig 10.7.0.5 10.7.0.6 (on host A)\n");
    printf("    --ifconfig 10.7.0.6 10.7.0.5 (on host B)\n");
    printf("because [5,6] is part of the below list.\n\n");

    for (i = 0; i < 256; i += 4)
    {
        printf("[%3d,%3d] ", i+1, i+2);
        if (++col > 4)
        {
            col = 0;
            printf("\n");
        }
    }
    if (col)
    {
        printf("\n");
    }
}

void
show_tap_win_adapters(int msglev, int warnlev)
{
    struct gc_arena gc = gc_new();

    bool warn_panel_null = false;
    bool warn_panel_dup = false;
    bool warn_tap_dup = false;

    int links;

    const struct tap_reg *tr;
    const struct tap_reg *tr1;
    const struct panel_reg *pr;

    const struct tap_reg *tap_reg = get_tap_reg(&gc);
    const struct panel_reg *panel_reg = get_panel_reg(&gc);

    msg(msglev, "Available adapters [name, GUID, driver]:");

    /* loop through each TAP-Windows adapter registry entry */
    for (tr = tap_reg; tr != NULL; tr = tr->next)
    {
        links = 0;

        /* loop through each network connections entry in the control panel */
        for (pr = panel_reg; pr != NULL; pr = pr->next)
        {
            if (!strcmp(tr->guid, pr->guid))
            {
                msg(msglev, "'%s' %s %s", pr->name, tr->guid, print_windows_driver(tr->windows_driver));
                ++links;
            }
        }

        if (links > 1)
        {
            warn_panel_dup = true;
        }
        else if (links == 0)
        {
            /* a TAP adapter exists without a link from the network
             * connections control panel */
            warn_panel_null = true;
            msg(msglev, "[NULL] %s", tr->guid);
        }
    }

    /* check for TAP-Windows adapter duplicated GUIDs */
    for (tr = tap_reg; tr != NULL; tr = tr->next)
    {
        for (tr1 = tap_reg; tr1 != NULL; tr1 = tr1->next)
        {
            if (tr != tr1 && !strcmp(tr->guid, tr1->guid))
            {
                warn_tap_dup = true;
            }
        }
    }

    /* warn on registry inconsistencies */
    if (warn_tap_dup)
    {
        msg(warnlev, "WARNING: Some TAP-Windows adapters have duplicate GUIDs");
    }

    if (warn_panel_dup)
    {
        msg(warnlev, "WARNING: Some TAP-Windows adapters have duplicate links from the Network Connections control panel");
    }

    if (warn_panel_null)
    {
        msg(warnlev, "WARNING: Some TAP-Windows adapters have no link from the Network Connections control panel");
    }

    gc_free(&gc);
}

/*
 * Lookup a TAP-Windows or Wintun adapter by GUID.
 */
static const struct tap_reg *
get_adapter_by_guid(const char *guid, const struct tap_reg *tap_reg)
{
    const struct tap_reg *tr;

    for (tr = tap_reg; tr != NULL; tr = tr->next)
    {
        if (guid && !strcmp(tr->guid, guid))
        {
            return tr;
        }
    }

    return NULL;
}

static const char *
guid_to_name(const char *guid, const struct panel_reg *panel_reg)
{
    const struct panel_reg *pr;

    for (pr = panel_reg; pr != NULL; pr = pr->next)
    {
        if (guid && !strcmp(pr->guid, guid))
        {
            return pr->name;
        }
    }

    return NULL;
}

static const struct tap_reg *
get_adapter_by_name(const char *name, const struct tap_reg *tap_reg, const struct panel_reg *panel_reg)
{
    const struct panel_reg *pr;

    for (pr = panel_reg; pr != NULL; pr = pr->next)
    {
        if (name && !strcmp(pr->name, name))
        {
            return get_adapter_by_guid(pr->guid, tap_reg);
        }
    }

    return NULL;
}

static void
at_least_one_tap_win(const struct tap_reg *tap_reg)
{
    if (!tap_reg)
    {
        msg(M_FATAL, "There are no TAP-Windows, Wintun or ovpn-dco adapters "
            "on this system.  You should be able to create an adapter "
            "by using tapctl.exe utility.");
    }
}

/*
 * Get an adapter GUID and optional actual_name from the
 * registry for the TAP device # = device_number.
 */
static const char *
get_unspecified_device_guid(const int device_number,
                            uint8_t *actual_name,
                            int actual_name_size,
                            const struct tap_reg *tap_reg_src,
                            const struct panel_reg *panel_reg_src,
                            enum windows_driver_type *windows_driver,
                            struct gc_arena *gc)
{
    const struct tap_reg *tap_reg = tap_reg_src;
    struct buffer actual = clear_buf();
    int i;

    ASSERT(device_number >= 0);

    /* Make sure we have at least one TAP adapter */
    if (!tap_reg)
    {
        return NULL;
    }

    /* The actual_name output buffer may be NULL */
    if (actual_name)
    {
        ASSERT(actual_name_size > 0);
        buf_set_write(&actual, actual_name, actual_name_size);
    }

    /* Move on to specified device number */
    for (i = 0; i < device_number; i++)
    {
        tap_reg = tap_reg->next;
        if (!tap_reg)
        {
            return NULL;
        }
    }

    /* Save Network Panel name (if exists) in actual_name */
    if (actual_name)
    {
        const char *act = guid_to_name(tap_reg->guid, panel_reg_src);
        if (act)
        {
            buf_printf(&actual, "%s", act);
        }
        else
        {
            buf_printf(&actual, "%s", tap_reg->guid);
        }
    }

    /* Save GUID for return value */
    struct buffer ret = alloc_buf_gc(256, gc);
    buf_printf(&ret, "%s", tap_reg->guid);
    if (windows_driver != NULL)
    {
        *windows_driver = tap_reg->windows_driver;
    }
    return BSTR(&ret);
}

/*
 * Lookup a --dev-node adapter name in the registry
 * returning the GUID and optional actual_name and device type
 */
static const char *
get_device_guid(const char *name,
                uint8_t *actual_name,
                int actual_name_size,
                enum windows_driver_type *windows_driver,
                const struct tap_reg *tap_reg,
                const struct panel_reg *panel_reg,
                struct gc_arena *gc)
{
    struct buffer ret = alloc_buf_gc(256, gc);
    struct buffer actual = clear_buf();
    const struct tap_reg *tr;

    /* Make sure we have at least one TAP adapter */
    if (!tap_reg)
    {
        return NULL;
    }

    /* The actual_name output buffer may be NULL */
    if (actual_name)
    {
        ASSERT(actual_name_size > 0);
        buf_set_write(&actual, actual_name, actual_name_size);
    }

    /* Check if GUID was explicitly specified as --dev-node parameter */
    tr = get_adapter_by_guid(name, tap_reg);
    if (tr)
    {
        const char *act = guid_to_name(name, panel_reg);
        buf_printf(&ret, "%s", name);
        if (act)
        {
            buf_printf(&actual, "%s", act);
        }
        else
        {
            buf_printf(&actual, "%s", name);
        }
        if (windows_driver)
        {
            *windows_driver = tr->windows_driver;
        }
        return BSTR(&ret);
    }

    /* Lookup TAP adapter in network connections list */
    {
        tr = get_adapter_by_name(name, tap_reg, panel_reg);
        if (tr)
        {
            buf_printf(&actual, "%s", name);
            if (windows_driver)
            {
                *windows_driver = tr->windows_driver;
            }
            buf_printf(&ret, "%s", tr->guid);
            return BSTR(&ret);
        }
    }

    return NULL;
}

/*
 * Get adapter info list
 */
const IP_ADAPTER_INFO *
get_adapter_info_list(struct gc_arena *gc)
{
    ULONG size = 0;
    IP_ADAPTER_INFO *pi = NULL;
    DWORD status;

    if ((status = GetAdaptersInfo(NULL, &size)) != ERROR_BUFFER_OVERFLOW)
    {
        msg(M_INFO, "GetAdaptersInfo #1 failed (status=%u) : %s",
            (unsigned int)status,
            strerror_win32(status, gc));
    }
    else
    {
        pi = (PIP_ADAPTER_INFO) gc_malloc(size, false, gc);
        if ((status = GetAdaptersInfo(pi, &size)) != NO_ERROR)
        {
            msg(M_INFO, "GetAdaptersInfo #2 failed (status=%u) : %s",
                (unsigned int)status,
                strerror_win32(status, gc));
            pi = NULL;
        }
    }
    return pi;
}

const IP_PER_ADAPTER_INFO *
get_per_adapter_info(const DWORD index, struct gc_arena *gc)
{
    ULONG size = 0;
    IP_PER_ADAPTER_INFO *pi = NULL;
    DWORD status;

    if (index != TUN_ADAPTER_INDEX_INVALID)
    {
        if ((status = GetPerAdapterInfo(index, NULL, &size)) != ERROR_BUFFER_OVERFLOW)
        {
            msg(M_INFO, "GetPerAdapterInfo #1 failed (status=%u) : %s",
                (unsigned int)status,
                strerror_win32(status, gc));
        }
        else
        {
            pi = (PIP_PER_ADAPTER_INFO) gc_malloc(size, false, gc);
            if ((status = GetPerAdapterInfo((ULONG)index, pi, &size)) == ERROR_SUCCESS)
            {
                return pi;
            }
            else
            {
                msg(M_INFO, "GetPerAdapterInfo #2 failed (status=%u) : %s",
                    (unsigned int)status,
                    strerror_win32(status, gc));
            }
        }
    }
    return pi;
}

static const IP_INTERFACE_INFO *
get_interface_info_list(struct gc_arena *gc)
{
    ULONG size = 0;
    IP_INTERFACE_INFO *ii = NULL;
    DWORD status;

    if ((status = GetInterfaceInfo(NULL, &size)) != ERROR_INSUFFICIENT_BUFFER)
    {
        msg(M_INFO, "GetInterfaceInfo #1 failed (status=%u) : %s",
            (unsigned int)status,
            strerror_win32(status, gc));
    }
    else
    {
        ii = (PIP_INTERFACE_INFO) gc_malloc(size, false, gc);
        if ((status = GetInterfaceInfo(ii, &size)) == NO_ERROR)
        {
            return ii;
        }
        else
        {
            msg(M_INFO, "GetInterfaceInfo #2 failed (status=%u) : %s",
                (unsigned int)status,
                strerror_win32(status, gc));
        }
    }
    return ii;
}

static const IP_ADAPTER_INDEX_MAP *
get_interface_info(DWORD index, struct gc_arena *gc)
{
    const IP_INTERFACE_INFO *list = get_interface_info_list(gc);
    if (list)
    {
        int i;
        for (i = 0; i < list->NumAdapters; ++i)
        {
            const IP_ADAPTER_INDEX_MAP *inter = &list->Adapter[i];
            if (index == inter->Index)
            {
                return inter;
            }
        }
    }
    return NULL;
}

/*
 * Given an adapter index, return a pointer to the
 * IP_ADAPTER_INFO structure for that adapter.
 */

const IP_ADAPTER_INFO *
get_adapter(const IP_ADAPTER_INFO *ai, DWORD index)
{
    if (ai && index != TUN_ADAPTER_INDEX_INVALID)
    {
        const IP_ADAPTER_INFO *a;

        /* find index in the linked list */
        for (a = ai; a != NULL; a = a->Next)
        {
            if (a->Index == index)
            {
                return a;
            }
        }
    }
    return NULL;
}

const IP_ADAPTER_INFO *
get_adapter_info(DWORD index, struct gc_arena *gc)
{
    return get_adapter(get_adapter_info_list(gc), index);
}

static int
get_adapter_n_ip_netmask(const IP_ADAPTER_INFO *ai)
{
    if (ai)
    {
        int n = 0;
        const IP_ADDR_STRING *ip = &ai->IpAddressList;

        while (ip)
        {
            ++n;
            ip = ip->Next;
        }
        return n;
    }
    else
    {
        return 0;
    }
}

static bool
get_adapter_ip_netmask(const IP_ADAPTER_INFO *ai, const int n, in_addr_t *ip, in_addr_t *netmask)
{
    bool ret = false;
    *ip = 0;
    *netmask = 0;

    if (ai)
    {
        const IP_ADDR_STRING *iplist = &ai->IpAddressList;
        int i = 0;

        while (iplist)
        {
            if (i == n)
            {
                break;
            }
            ++i;
            iplist = iplist->Next;
        }

        if (iplist)
        {
            const unsigned int getaddr_flags = GETADDR_HOST_ORDER;
            const char *ip_str = iplist->IpAddress.String;
            const char *netmask_str = iplist->IpMask.String;
            bool succeed1 = false;
            bool succeed2 = false;

            if (ip_str && netmask_str && strlen(ip_str) && strlen(netmask_str))
            {
                *ip = getaddr(getaddr_flags, ip_str, 0, &succeed1, NULL);
                *netmask = getaddr(getaddr_flags, netmask_str, 0, &succeed2, NULL);
                ret = (succeed1 == true && succeed2 == true);
            }
        }
    }

    return ret;
}

static bool
test_adapter_ip_netmask(const IP_ADAPTER_INFO *ai, const in_addr_t ip, const in_addr_t netmask)
{
    if (ai)
    {
        in_addr_t ip_adapter = 0;
        in_addr_t netmask_adapter = 0;
        const bool status = get_adapter_ip_netmask(ai, 0, &ip_adapter, &netmask_adapter);
        return (status && ip_adapter == ip && netmask_adapter == netmask);
    }
    else
    {
        return false;
    }
}

const IP_ADAPTER_INFO *
get_tun_adapter(const struct tuntap *tt, const IP_ADAPTER_INFO *list)
{
    if (list && tt)
    {
        return get_adapter(list, tt->adapter_index);
    }
    else
    {
        return NULL;
    }
}

bool
is_adapter_up(const struct tuntap *tt, const IP_ADAPTER_INFO *list)
{
    int i;
    bool ret = false;

    const IP_ADAPTER_INFO *ai = get_tun_adapter(tt, list);

    if (ai)
    {
        const int n = get_adapter_n_ip_netmask(ai);

        /* loop once for every IP/netmask assigned to adapter */
        for (i = 0; i < n; ++i)
        {
            in_addr_t ip, netmask;
            if (get_adapter_ip_netmask(ai, i, &ip, &netmask))
            {
                if (tt->local && tt->adapter_netmask)
                {
                    /* wait for our --ifconfig parms to match the actual adapter parms */
                    if (tt->local == ip && tt->adapter_netmask == netmask)
                    {
                        ret = true;
                    }
                }
                else
                {
                    /* --ifconfig was not defined, maybe using a real DHCP server */
                    if (ip && netmask)
                    {
                        ret = true;
                    }
                }
            }
        }
    }
    else
    {
        ret = true; /* this can occur when TAP adapter is bridged */

    }
    return ret;
}

bool
is_ip_in_adapter_subnet(const IP_ADAPTER_INFO *ai, const in_addr_t ip, in_addr_t *highest_netmask)
{
    int i;
    bool ret = false;

    if (highest_netmask)
    {
        *highest_netmask = 0;
    }

    if (ai)
    {
        const int n = get_adapter_n_ip_netmask(ai);
        for (i = 0; i < n; ++i)
        {
            in_addr_t adapter_ip, adapter_netmask;
            if (get_adapter_ip_netmask(ai, i, &adapter_ip, &adapter_netmask))
            {
                if (adapter_ip && adapter_netmask && (ip & adapter_netmask) == (adapter_ip & adapter_netmask))
                {
                    if (highest_netmask && adapter_netmask > *highest_netmask)
                    {
                        *highest_netmask = adapter_netmask;
                    }
                    ret = true;
                }
            }
        }
    }
    return ret;
}

DWORD
adapter_index_of_ip(const IP_ADAPTER_INFO *list,
                    const in_addr_t ip,
                    int *count,
                    in_addr_t *netmask)
{
    struct gc_arena gc = gc_new();
    DWORD ret = TUN_ADAPTER_INDEX_INVALID;
    in_addr_t highest_netmask = 0;
    int lowest_metric = INT_MAX;
    bool first = true;

    if (count)
    {
        *count = 0;
    }

    while (list)
    {
        in_addr_t hn;

        if (is_ip_in_adapter_subnet(list, ip, &hn))
        {
            int metric = get_interface_metric(list->Index, AF_INET, NULL);
            if (first || hn > highest_netmask)
            {
                highest_netmask = hn;
                if (metric >= 0)
                {
                    lowest_metric = metric;
                }
                if (count)
                {
                    *count = 1;
                }
                ret = list->Index;
                first = false;
            }
            else if (hn == highest_netmask)
            {
                if (count)
                {
                    ++*count;
                }
                if (metric >= 0 && metric < lowest_metric)
                {
                    ret = list->Index;
                    lowest_metric = metric;
                }
            }
        }
        list = list->Next;
    }

    dmsg(D_ROUTE_DEBUG, "DEBUG: IP Locate: ip=%s nm=%s index=%d count=%d metric=%d",
         print_in_addr_t(ip, 0, &gc),
         print_in_addr_t(highest_netmask, 0, &gc),
         (int)ret,
         count ? *count : -1,
         lowest_metric);

    if (ret == TUN_ADAPTER_INDEX_INVALID && count)
    {
        *count = 0;
    }

    if (netmask)
    {
        *netmask = highest_netmask;
    }

    gc_free(&gc);
    return ret;
}

/*
 * Given an adapter index, return true if the adapter
 * is DHCP disabled.
 */

#define DHCP_STATUS_UNDEF     0
#define DHCP_STATUS_ENABLED   1
#define DHCP_STATUS_DISABLED  2

static int
dhcp_status(DWORD index)
{
    struct gc_arena gc = gc_new();
    int ret = DHCP_STATUS_UNDEF;
    if (index != TUN_ADAPTER_INDEX_INVALID)
    {
        const IP_ADAPTER_INFO *ai = get_adapter_info(index, &gc);

        if (ai)
        {
            if (ai->DhcpEnabled)
            {
                ret = DHCP_STATUS_ENABLED;
            }
            else
            {
                ret = DHCP_STATUS_DISABLED;
            }
        }
    }
    gc_free(&gc);
    return ret;
}

/*
 * Delete all temporary address/netmask pairs which were added
 * to adapter (given by index) by previous calls to AddIPAddress.
 */
static void
delete_temp_addresses(DWORD index)
{
    struct gc_arena gc = gc_new();
    const IP_ADAPTER_INFO *a = get_adapter_info(index, &gc);

    if (a)
    {
        const IP_ADDR_STRING *ip = &a->IpAddressList;
        while (ip)
        {
            DWORD status;
            const DWORD context = ip->Context;

            if ((status = DeleteIPAddress((ULONG) context)) == NO_ERROR)
            {
                msg(M_INFO, "Successfully deleted previously set dynamic IP/netmask: %s/%s",
                    ip->IpAddress.String,
                    ip->IpMask.String);
            }
            else
            {
                const char *empty = "0.0.0.0";
                if (strcmp(ip->IpAddress.String, empty)
                    || strcmp(ip->IpMask.String, empty))
                {
                    msg(M_INFO, "NOTE: could not delete previously set dynamic IP/netmask: %s/%s (status=%u)",
                        ip->IpAddress.String,
                        ip->IpMask.String,
                        (unsigned int)status);
                }
            }
            ip = ip->Next;
        }
    }
    gc_free(&gc);
}

/*
 * Get interface index for use with IP Helper API functions.
 */
static DWORD
get_adapter_index_method_1(const char *guid)
{
    DWORD index;
    ULONG aindex;
    wchar_t wbuf[256];
    openvpn_swprintf(wbuf, SIZE(wbuf), L"\\DEVICE\\TCPIP_%hs", guid);
    if (GetAdapterIndex(wbuf, &aindex) != NO_ERROR)
    {
        index = TUN_ADAPTER_INDEX_INVALID;
    }
    else
    {
        index = (DWORD)aindex;
    }
    return index;
}

static DWORD
get_adapter_index_method_2(const char *guid)
{
    struct gc_arena gc = gc_new();
    DWORD index = TUN_ADAPTER_INDEX_INVALID;

    const IP_ADAPTER_INFO *list = get_adapter_info_list(&gc);

    while (list)
    {
        if (!strcmp(guid, list->AdapterName))
        {
            index = list->Index;
            break;
        }
        list = list->Next;
    }

    gc_free(&gc);
    return index;
}

static DWORD
get_adapter_index(const char *guid)
{
    DWORD index;
    index = get_adapter_index_method_1(guid);
    if (index == TUN_ADAPTER_INDEX_INVALID)
    {
        index = get_adapter_index_method_2(guid);
    }
    if (index == TUN_ADAPTER_INDEX_INVALID)
    {
        msg(M_INFO, "NOTE: could not get adapter index for %s", guid);
    }
    return index;
}

/*
 * Return a string representing a PIP_ADDR_STRING
 */
static const char *
format_ip_addr_string(const IP_ADDR_STRING *ip, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);
    while (ip)
    {
        buf_printf(&out, "%s", ip->IpAddress.String);
        if (strlen(ip->IpMask.String))
        {
            buf_printf(&out, "/");
            buf_printf(&out, "%s", ip->IpMask.String);
        }
        buf_printf(&out, " ");
        ip = ip->Next;
    }
    return BSTR(&out);
}

/*
 * Show info for a single adapter
 */
static void
show_adapter(int msglev, const IP_ADAPTER_INFO *a, struct gc_arena *gc)
{
    msg(msglev, "%s", a->Description);
    msg(msglev, "  Index = %d", (int)a->Index);
    msg(msglev, "  GUID = %s", a->AdapterName);
    msg(msglev, "  IP = %s", format_ip_addr_string(&a->IpAddressList, gc));
    msg(msglev, "  MAC = %s", format_hex_ex(a->Address, a->AddressLength, 0, 1, ":", gc));
    msg(msglev, "  GATEWAY = %s", format_ip_addr_string(&a->GatewayList, gc));
    if (a->DhcpEnabled)
    {
        msg(msglev, "  DHCP SERV = %s", format_ip_addr_string(&a->DhcpServer, gc));
        msg(msglev, "  DHCP LEASE OBTAINED = %s", time_string(a->LeaseObtained, 0, false, gc));
        msg(msglev, "  DHCP LEASE EXPIRES  = %s", time_string(a->LeaseExpires, 0, false, gc));
    }
    if (a->HaveWins)
    {
        msg(msglev, "  PRI WINS = %s", format_ip_addr_string(&a->PrimaryWinsServer, gc));
        msg(msglev, "  SEC WINS = %s", format_ip_addr_string(&a->SecondaryWinsServer, gc));
    }

    {
        const IP_PER_ADAPTER_INFO *pai = get_per_adapter_info(a->Index, gc);
        if (pai)
        {
            msg(msglev, "  DNS SERV = %s", format_ip_addr_string(&pai->DnsServerList, gc));
        }
    }
}

/*
 * Show current adapter list
 */
void
show_adapters(int msglev)
{
    struct gc_arena gc = gc_new();
    const IP_ADAPTER_INFO *ai = get_adapter_info_list(&gc);

    msg(msglev, "SYSTEM ADAPTER LIST");
    if (ai)
    {
        const IP_ADAPTER_INFO *a;

        /* find index in the linked list */
        for (a = ai; a != NULL; a = a->Next)
        {
            show_adapter(msglev, a, &gc);
        }
    }
    gc_free(&gc);
}

/*
 * Set a particular TAP-Windows adapter (or all of them if
 * adapter_name == NULL) to allow it to be opened from
 * a non-admin account.  This setting will only persist
 * for the lifetime of the device object.
 */

static void
tap_allow_nonadmin_access_handle(const char *device_path, HANDLE hand)
{
    struct security_attributes sa;
    BOOL status;

    if (!init_security_attributes_allow_all(&sa))
    {
        msg(M_ERR, "Error: init SA failed");
    }

    status = SetKernelObjectSecurity(hand, DACL_SECURITY_INFORMATION, &sa.sd);
    if (!status)
    {
        msg(M_ERRNO, "Error: SetKernelObjectSecurity failed on %s", device_path);
    }
    else
    {
        msg(M_INFO|M_NOPREFIX, "TAP-Windows device: %s [Non-admin access allowed]", device_path);
    }
}

void
tap_allow_nonadmin_access(const char *dev_node)
{
    struct gc_arena gc = gc_new();
    const struct tap_reg *tap_reg = get_tap_reg(&gc);
    const struct panel_reg *panel_reg = get_panel_reg(&gc);
    const char *device_guid = NULL;
    HANDLE hand;
    uint8_t actual_buffer[256];
    char device_path[256];

    at_least_one_tap_win(tap_reg);

    if (dev_node)
    {
        /* Get the device GUID for the device specified with --dev-node. */
        device_guid = get_device_guid(dev_node, actual_buffer, sizeof(actual_buffer), NULL, tap_reg, panel_reg, &gc);

        if (!device_guid)
        {
            msg(M_FATAL, "TAP-Windows adapter '%s' not found", dev_node);
        }

        /* Open Windows TAP-Windows adapter */
        openvpn_snprintf(device_path, sizeof(device_path), "%s%s%s",
                         USERMODEDEVICEDIR,
                         device_guid,
                         TAP_WIN_SUFFIX);

        hand = CreateFile(
            device_path,
            MAXIMUM_ALLOWED,
            0,              /* was: FILE_SHARE_READ */
            0,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
            0
            );

        if (hand == INVALID_HANDLE_VALUE)
        {
            msg(M_ERR, "CreateFile failed on TAP device: %s", device_path);
        }

        tap_allow_nonadmin_access_handle(device_path, hand);
        CloseHandle(hand);
    }
    else
    {
        int device_number = 0;

        /* Try opening all TAP devices */
        while (true)
        {
            device_guid = get_unspecified_device_guid(device_number,
                                                      actual_buffer,
                                                      sizeof(actual_buffer),
                                                      tap_reg,
                                                      panel_reg,
                                                      NULL,
                                                      &gc);

            if (!device_guid)
            {
                break;
            }

            /* Open Windows TAP-Windows adapter */
            openvpn_snprintf(device_path, sizeof(device_path), "%s%s%s",
                             USERMODEDEVICEDIR,
                             device_guid,
                             TAP_WIN_SUFFIX);

            hand = CreateFile(
                device_path,
                MAXIMUM_ALLOWED,
                0,              /* was: FILE_SHARE_READ */
                0,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                0
                );

            if (hand == INVALID_HANDLE_VALUE)
            {
                msg(M_WARN, "CreateFile failed on TAP device: %s", device_path);
            }
            else
            {
                tap_allow_nonadmin_access_handle(device_path, hand);
                CloseHandle(hand);
            }

            device_number++;
        }
    }
    gc_free(&gc);
}

/*
 * DHCP release/renewal
 */
bool
dhcp_release_by_adapter_index(const DWORD adapter_index)
{
    struct gc_arena gc = gc_new();
    bool ret = false;
    const IP_ADAPTER_INDEX_MAP *inter = get_interface_info(adapter_index, &gc);

    if (inter)
    {
        DWORD status = IpReleaseAddress((IP_ADAPTER_INDEX_MAP *)inter);
        if (status == NO_ERROR)
        {
            msg(D_TUNTAP_INFO, "TAP: DHCP address released");
            ret = true;
        }
        else
        {
            msg(M_WARN, "NOTE: Release of DHCP-assigned IP address lease on TAP-Windows adapter failed: %s (code=%u)",
                strerror_win32(status, &gc),
                (unsigned int)status);
        }
    }

    gc_free(&gc);
    return ret;
}

static bool
dhcp_release(const struct tuntap *tt)
{
    if (tt && tt->options.ip_win32_type == IPW32_SET_DHCP_MASQ && tt->adapter_index != TUN_ADAPTER_INDEX_INVALID)
    {
        return dhcp_release_by_adapter_index(tt->adapter_index);
    }
    else
    {
        return false;
    }
}

bool
dhcp_renew_by_adapter_index(const DWORD adapter_index)
{
    struct gc_arena gc = gc_new();
    bool ret = false;
    const IP_ADAPTER_INDEX_MAP *inter = get_interface_info(adapter_index, &gc);

    if (inter)
    {
        DWORD status = IpRenewAddress((IP_ADAPTER_INDEX_MAP *)inter);
        if (status == NO_ERROR)
        {
            msg(D_TUNTAP_INFO, "TAP: DHCP address renewal succeeded");
            ret = true;
        }
        else
        {
            msg(M_WARN, "WARNING: Failed to renew DHCP IP address lease on TAP-Windows adapter: %s (code=%u)",
                strerror_win32(status, &gc),
                (unsigned int)status);
        }
    }
    gc_free(&gc);
    return ret;
}

static bool
dhcp_renew(const struct tuntap *tt)
{
    if (tt && tt->options.ip_win32_type == IPW32_SET_DHCP_MASQ && tt->adapter_index != TUN_ADAPTER_INDEX_INVALID)
    {
        return dhcp_renew_by_adapter_index(tt->adapter_index);
    }
    else
    {
        return false;
    }
}

static void
exec_command(const char *prefix, const struct argv *a, int n, int msglevel)
{
    int i;
    for (i = 0; i < n; ++i)
    {
        bool status;
        management_sleep(0);
        netcmd_semaphore_lock();
        argv_msg_prefix(M_INFO, a, prefix);
        status = openvpn_execve_check(a, NULL, 0, "ERROR: command failed");
        netcmd_semaphore_release();
        if (status)
        {
            return;
        }
        management_sleep(4);
    }
    msg(msglevel, "%s: command failed", prefix);
}

static void
netsh_command(const struct argv *a, int n, int msglevel)
{
    exec_command("NETSH", a, n, msglevel);
}

void
ipconfig_register_dns(const struct env_set *es)
{
    struct argv argv = argv_new();
    const char err[] = "ERROR: Windows ipconfig command failed";

    msg(D_TUNTAP_INFO, "Start ipconfig commands for register-dns...");
    netcmd_semaphore_lock();

    argv_printf(&argv, "%s%s /flushdns",
                get_win_sys_path(),
                WIN_IPCONFIG_PATH_SUFFIX);
    argv_msg(D_TUNTAP_INFO, &argv);
    openvpn_execve_check(&argv, es, 0, err);

    argv_printf(&argv, "%s%s /registerdns",
                get_win_sys_path(),
                WIN_IPCONFIG_PATH_SUFFIX);
    argv_msg(D_TUNTAP_INFO, &argv);
    openvpn_execve_check(&argv, es, 0, err);
    argv_free(&argv);

    netcmd_semaphore_release();
    msg(D_TUNTAP_INFO, "End ipconfig commands for register-dns...");
}

void
ip_addr_string_to_array(in_addr_t *dest, int *dest_len, const IP_ADDR_STRING *src)
{
    int i = 0;
    while (src)
    {
        const unsigned int getaddr_flags = GETADDR_HOST_ORDER;
        const char *ip_str = src->IpAddress.String;
        in_addr_t ip = 0;
        bool succeed = false;

        if (i >= *dest_len)
        {
            break;
        }
        if (!ip_str || !strlen(ip_str))
        {
            break;
        }

        ip = getaddr(getaddr_flags, ip_str, 0, &succeed, NULL);
        if (!succeed)
        {
            break;
        }
        dest[i++] = ip;

        src = src->Next;
    }
    *dest_len = i;

#if 0
    {
        struct gc_arena gc = gc_new();
        msg(M_INFO, "ip_addr_string_to_array [%d]", *dest_len);
        for (i = 0; i < *dest_len; ++i)
        {
            msg(M_INFO, "%s", print_in_addr_t(dest[i], 0, &gc));
        }
        gc_free(&gc);
    }
#endif
}

static bool
ip_addr_one_to_one(const in_addr_t *a1, const int a1len, const IP_ADDR_STRING *ias)
{
    in_addr_t a2[8];
    int a2len = SIZE(a2);
    int i;

    ip_addr_string_to_array(a2, &a2len, ias);
    /*msg (M_INFO, "a1len=%d a2len=%d", a1len, a2len);*/
    if (a1len != a2len)
    {
        return false;
    }

    for (i = 0; i < a1len; ++i)
    {
        if (a1[i] != a2[i])
        {
            return false;
        }
    }
    return true;
}

static bool
ip_addr_member_of(const in_addr_t addr, const IP_ADDR_STRING *ias)
{
    in_addr_t aa[8];
    int len = SIZE(aa);
    int i;

    ip_addr_string_to_array(aa, &len, ias);
    for (i = 0; i < len; ++i)
    {
        if (addr == aa[i])
        {
            return true;
        }
    }
    return false;
}

/**
 * Set the ipv6 dns servers on the specified interface.
 * The list of dns servers currently set on the interface
 * are cleared first.
 */
static void
netsh_set_dns6_servers(const struct in6_addr *addr_list,
                       const int addr_len,
                       DWORD adapter_index)
{
    struct gc_arena gc = gc_new();
    struct argv argv = argv_new();

    /* delete existing DNS settings from TAP interface */
    argv_printf(&argv, "%s%s interface ipv6 delete dns %lu all",
                get_win_sys_path(),
                NETSH_PATH_SUFFIX,
                adapter_index);
    netsh_command(&argv, 2, M_FATAL);

    for (int i = 0; i < addr_len; ++i)
    {
        const char *fmt = (i == 0) ?
                          "%s%s interface ipv6 set dns %lu static %s"
                          : "%s%s interface ipv6 add dns %lu %s";
        argv_printf(&argv, fmt, get_win_sys_path(),
                    NETSH_PATH_SUFFIX, adapter_index,
                    print_in6_addr(addr_list[i], 0, &gc));

        /* disable slow address validation on Windows 7 and higher */
        if (win32_version_info() >= WIN_7)
        {
            argv_printf_cat(&argv, "%s", "validate=no");
        }

        /* Treat errors while adding as non-fatal as we do not check for duplicates */
        netsh_command(&argv, 1, (i==0) ? M_FATAL : M_NONFATAL);
    }

    argv_free(&argv);
    gc_free(&gc);
}

static void
netsh_ifconfig_options(const char *type,
                       const in_addr_t *addr_list,
                       const int addr_len,
                       const IP_ADDR_STRING *current,
                       DWORD adapter_index,
                       const bool test_first)
{
    struct gc_arena gc = gc_new();
    struct argv argv = argv_new();
    bool delete_first = false;
    bool is_dns = !strcmp(type, "dns");

    /* first check if we should delete existing DNS/WINS settings from TAP interface */
    if (test_first)
    {
        if (!ip_addr_one_to_one(addr_list, addr_len, current))
        {
            delete_first = true;
        }
    }
    else
    {
        delete_first = true;
    }

    /* delete existing DNS/WINS settings from TAP interface */
    if (delete_first)
    {
        argv_printf(&argv, "%s%s interface ip delete %s %lu all",
                    get_win_sys_path(),
                    NETSH_PATH_SUFFIX,
                    type,
                    adapter_index);
        netsh_command(&argv, 2, M_FATAL);
    }

    /* add new DNS/WINS settings to TAP interface */
    {
        int count = 0;
        int i;
        for (i = 0; i < addr_len; ++i)
        {
            if (delete_first || !test_first || !ip_addr_member_of(addr_list[i], current))
            {
                const char *fmt = count ?
                                  "%s%s interface ip add %s %lu %s"
                                  : "%s%s interface ip set %s %lu static %s";

                argv_printf(&argv, fmt,
                            get_win_sys_path(),
                            NETSH_PATH_SUFFIX,
                            type,
                            adapter_index,
                            print_in_addr_t(addr_list[i], 0, &gc));

                /* disable slow address validation on Windows 7 and higher */
                /* only for DNS */
                if (is_dns && win32_version_info() >= WIN_7)
                {
                    argv_printf_cat(&argv, "%s", "validate=no");
                }

                netsh_command(&argv, 2, M_FATAL);

                ++count;
            }
            else
            {
                msg(M_INFO, "NETSH: %lu %s %s [already set]",
                    adapter_index,
                    type,
                    print_in_addr_t(addr_list[i], 0, &gc));
            }
        }
    }

    argv_free(&argv);
    gc_free(&gc);
}

static void
init_ip_addr_string2(IP_ADDR_STRING *dest, const IP_ADDR_STRING *src1, const IP_ADDR_STRING *src2)
{
    CLEAR(dest[0]);
    CLEAR(dest[1]);
    if (src1)
    {
        dest[0] = *src1;
        dest[0].Next = NULL;
    }
    if (src2)
    {
        dest[1] = *src2;
        dest[0].Next = &dest[1];
        dest[1].Next = NULL;
    }
}

static void
netsh_ifconfig(const struct tuntap_options *to,
               DWORD adapter_index,
               const in_addr_t ip,
               const in_addr_t netmask,
               const unsigned int flags)
{
    struct gc_arena gc = gc_new();
    struct argv argv = argv_new();
    const IP_ADAPTER_INFO *ai = NULL;
    const IP_PER_ADAPTER_INFO *pai = NULL;

    if (flags & NI_TEST_FIRST)
    {
        const IP_ADAPTER_INFO *list = get_adapter_info_list(&gc);
        ai = get_adapter(list, adapter_index);
        pai = get_per_adapter_info(adapter_index, &gc);
    }

    if (flags & NI_IP_NETMASK)
    {
        if (test_adapter_ip_netmask(ai, ip, netmask))
        {
            msg(M_INFO, "NETSH: %lu %s/%s [already set]",
                adapter_index,
                print_in_addr_t(ip, 0, &gc),
                print_in_addr_t(netmask, 0, &gc));
        }
        else
        {
            /* example: netsh interface ip set address 42 static 10.3.0.1 255.255.255.0 */
            argv_printf(&argv, "%s%s interface ip set address %lu static %s %s",
                        get_win_sys_path(),
                        NETSH_PATH_SUFFIX,
                        adapter_index,
                        print_in_addr_t(ip, 0, &gc),
                        print_in_addr_t(netmask, 0, &gc));

            netsh_command(&argv, 4, M_FATAL);
        }
    }

    /* set WINS/DNS options */
    if (flags & NI_OPTIONS)
    {
        IP_ADDR_STRING wins[2];
        CLEAR(wins[0]);
        CLEAR(wins[1]);

        netsh_ifconfig_options("dns",
                               to->dns,
                               to->dns_len,
                               pai ? &pai->DnsServerList : NULL,
                               adapter_index,
                               BOOL_CAST(flags & NI_TEST_FIRST));
        if (ai && ai->HaveWins)
        {
            init_ip_addr_string2(wins, &ai->PrimaryWinsServer, &ai->SecondaryWinsServer);
        }

        netsh_ifconfig_options("wins",
                               to->wins,
                               to->wins_len,
                               ai ? wins : NULL,
                               adapter_index,
                               BOOL_CAST(flags & NI_TEST_FIRST));
    }

    argv_free(&argv);
    gc_free(&gc);
}

static void
netsh_enable_dhcp(DWORD adapter_index)
{
    struct argv argv = argv_new();

    /* example: netsh interface ip set address 42 dhcp */
    argv_printf(&argv,
                "%s%s interface ip set address %lu dhcp",
                get_win_sys_path(),
                NETSH_PATH_SUFFIX,
                adapter_index);

    netsh_command(&argv, 4, M_FATAL);

    argv_free(&argv);
}

/* Enable dhcp on tap adapter using iservice */
static bool
service_enable_dhcp(const struct tuntap *tt)
{
    bool ret = false;
    ack_message_t ack;
    struct gc_arena gc = gc_new();
    HANDLE pipe = tt->options.msg_channel;

    enable_dhcp_message_t dhcp = {
        .header = {
            msg_enable_dhcp,
            sizeof(enable_dhcp_message_t),
            0
        },
        .iface = { .index = tt->adapter_index, .name = "" }
    };

    if (!send_msg_iservice(pipe, &dhcp, sizeof(dhcp), &ack, "Enable_dhcp"))
    {
        goto out;
    }

    if (ack.error_number != NO_ERROR)
    {
        msg(M_NONFATAL, "TUN: enabling dhcp using service failed: %s [status=%u if_index=%d]",
            strerror_win32(ack.error_number, &gc), ack.error_number, dhcp.iface.index);
    }
    else
    {
        msg(M_INFO, "DHCP enabled on interface %d using service", dhcp.iface.index);
        ret = true;
    }

out:
    gc_free(&gc);
    return ret;
}

static void
windows_set_mtu(const int iface_index, const short family,
                const int mtu)
{
    DWORD err = 0;
    struct gc_arena gc = gc_new();
    MIB_IPINTERFACE_ROW ipiface;
    InitializeIpInterfaceEntry(&ipiface);
    const char *family_name = (family == AF_INET6) ? "IPv6" : "IPv4";
    ipiface.Family = family;
    ipiface.InterfaceIndex = iface_index;
    if (family == AF_INET6 && mtu < 1280)
    {
        msg(M_INFO, "NOTE: IPv6 interface MTU < 1280 conflicts with IETF standards and might not work");
    }

    err = GetIpInterfaceEntry(&ipiface);
    if (err == NO_ERROR)
    {
        if (family == AF_INET)
        {
            ipiface.SitePrefixLength = 0;
        }
        ipiface.NlMtu = mtu;
        err = SetIpInterfaceEntry(&ipiface);
    }

    if (err != NO_ERROR)
    {
        msg(M_WARN, "TUN: Setting %s mtu failed: %s [status=%lu if_index=%d]",
            family_name, strerror_win32(err, &gc), err, iface_index);
    }
    else
    {
        msg(M_INFO, "%s MTU set to %d on interface %d using SetIpInterfaceEntry()", family_name, mtu, iface_index);
    }
}


/*
 * Return a TAP name for netsh commands.
 */
static const char *
netsh_get_id(const char *dev_node, struct gc_arena *gc)
{
    const struct tap_reg *tap_reg = get_tap_reg(gc);
    const struct panel_reg *panel_reg = get_panel_reg(gc);
    struct buffer actual = alloc_buf_gc(256, gc);
    const char *guid;

    at_least_one_tap_win(tap_reg);

    if (dev_node)
    {
        guid = get_device_guid(dev_node, BPTR(&actual), BCAP(&actual), NULL, tap_reg, panel_reg, gc);
    }
    else
    {
        guid = get_unspecified_device_guid(0, BPTR(&actual), BCAP(&actual), tap_reg, panel_reg, NULL, gc);

        if (get_unspecified_device_guid(1, NULL, 0, tap_reg, panel_reg, NULL, gc)) /* ambiguous if more than one TAP-Windows adapter */
        {
            guid = NULL;
        }
    }

    if (!guid)
    {
        return "NULL";     /* not found */
    }
    else if (strcmp(BSTR(&actual), "NULL"))
    {
        return BSTR(&actual); /* control panel name */
    }
    else
    {
        return guid;       /* no control panel name, return GUID instead */
    }
}

/*
 * Called iteratively on TAP-Windows wait-for-initialization polling loop
 */
void
tun_standby_init(struct tuntap *tt)
{
    tt->standby_iter = 0;
}

bool
tun_standby(struct tuntap *tt)
{
    bool ret = true;
    ++tt->standby_iter;
    if (tt->options.ip_win32_type == IPW32_SET_ADAPTIVE)
    {
        if (tt->standby_iter == IPW32_SET_ADAPTIVE_TRY_NETSH)
        {
            msg(M_INFO, "NOTE: now trying netsh (this may take some time)");
            netsh_ifconfig(&tt->options,
                           tt->adapter_index,
                           tt->local,
                           tt->adapter_netmask,
                           NI_TEST_FIRST|NI_IP_NETMASK|NI_OPTIONS);
        }
        else if (tt->standby_iter >= IPW32_SET_ADAPTIVE_TRY_NETSH*2)
        {
            ret = false;
        }
    }
    return ret;
}

/*
 * Convert DHCP options from the command line / config file
 * into a raw DHCP-format options string.
 */

static void
write_dhcp_u8(struct buffer *buf, const int type, const int data, bool *error)
{
    if (!buf_safe(buf, 3))
    {
        *error = true;
        msg(M_WARN, "write_dhcp_u8: buffer overflow building DHCP options");
        return;
    }
    buf_write_u8(buf, type);
    buf_write_u8(buf, 1);
    buf_write_u8(buf, data);
}

static void
write_dhcp_u32_array(struct buffer *buf, const int type, const uint32_t *data, const unsigned int len, bool *error)
{
    if (len > 0)
    {
        int i;
        const int size = len * sizeof(uint32_t);

        if (!buf_safe(buf, 2 + size))
        {
            *error = true;
            msg(M_WARN, "write_dhcp_u32_array: buffer overflow building DHCP options");
            return;
        }
        if (size < 1 || size > 255)
        {
            *error = true;
            msg(M_WARN, "write_dhcp_u32_array: size (%d) must be > 0 and <= 255", size);
            return;
        }
        buf_write_u8(buf, type);
        buf_write_u8(buf, size);
        for (i = 0; i < len; ++i)
        {
            buf_write_u32(buf, data[i]);
        }
    }
}

static void
write_dhcp_str(struct buffer *buf, const int type, const char *str, bool *error)
{
    const int len = strlen(str);
    if (!buf_safe(buf, 2 + len))
    {
        *error = true;
        msg(M_WARN, "write_dhcp_str: buffer overflow building DHCP options");
        return;
    }
    if (len < 1 || len > 255)
    {
        *error = true;
        msg(M_WARN, "write_dhcp_str: string '%s' must be > 0 bytes and <= 255 bytes", str);
        return;
    }
    buf_write_u8(buf, type);
    buf_write_u8(buf, len);
    buf_write(buf, str, len);
}

/*
 * RFC3397 states that multiple searchdomains are encoded as follows:
 *  - at start the length of the entire option is given
 *  - each subdomain is preceded by its length
 *  - each searchdomain is separated by a NUL character
 * e.g. if you want "openvpn.net" and "duckduckgo.com" then you end up with
 *  0x1D  0x7 openvpn 0x3 net 0x00 0x0A duckduckgo 0x3 com 0x00
 */
static void
write_dhcp_search_str(struct buffer *buf, const int type, const char *const *str_array,
                      int array_len, bool *error)
{
    char tmp_buf[256];
    int i;
    int len = 0;
    int label_length_pos;

    for (i = 0; i < array_len; i++)
    {
        const char  *ptr = str_array[i];

        if (strlen(ptr) + len + 1 > sizeof(tmp_buf))
        {
            *error = true;
            msg(M_WARN, "write_dhcp_search_str: temp buffer overflow building DHCP options");
            return;
        }
        /* Loop over all subdomains separated by a dot and replace the dot
         * with the length of the subdomain */

        /* label_length_pos points to the byte to be replaced by the length
         * of the following domain label */
        label_length_pos = len++;

        while (true)
        {
            if (*ptr == '.' || *ptr == '\0')
            {
                tmp_buf[label_length_pos] = (len-label_length_pos)-1;
                label_length_pos = len;
                if (*ptr == '\0')
                {
                    break;
                }
            }
            tmp_buf[len++] = *ptr++;
        }
        /* And close off with an extra NUL char */
        tmp_buf[len++] = 0;
    }

    if (!buf_safe(buf, 2 + len))
    {
        *error = true;
        msg(M_WARN, "write_search_dhcp_str: buffer overflow building DHCP options");
        return;
    }
    if (len > 255)
    {
        *error = true;
        msg(M_WARN, "write_dhcp_search_str: search domain string must be <= 255 bytes");
        return;
    }

    buf_write_u8(buf, type);
    buf_write_u8(buf, len);
    buf_write(buf, tmp_buf, len);
}

static bool
build_dhcp_options_string(struct buffer *buf, const struct tuntap_options *o)
{
    bool error = false;
    if (o->domain)
    {
        write_dhcp_str(buf, 15, o->domain, &error);
    }

    if (o->netbios_scope)
    {
        write_dhcp_str(buf, 47, o->netbios_scope, &error);
    }

    if (o->netbios_node_type)
    {
        write_dhcp_u8(buf, 46, o->netbios_node_type, &error);
    }

    write_dhcp_u32_array(buf, 6, (uint32_t *)o->dns, o->dns_len, &error);
    write_dhcp_u32_array(buf, 44, (uint32_t *)o->wins, o->wins_len, &error);
    write_dhcp_u32_array(buf, 42, (uint32_t *)o->ntp, o->ntp_len, &error);
    write_dhcp_u32_array(buf, 45, (uint32_t *)o->nbdd, o->nbdd_len, &error);

    if (o->domain_search_list_len > 0)
    {
        write_dhcp_search_str(buf, 119, o->domain_search_list,
                              o->domain_search_list_len,
                              &error);
    }

    /* the MS DHCP server option 'Disable Netbios-over-TCP/IP
     * is implemented as vendor option 001, value 002.
     * A value of 001 means 'leave NBT alone' which is the default */
    if (o->disable_nbt)
    {
        if (!buf_safe(buf, 8))
        {
            msg(M_WARN, "build_dhcp_options_string: buffer overflow building DHCP options");
            return false;
        }
        buf_write_u8(buf,  43);
        buf_write_u8(buf,  6);/* total length field */
        buf_write_u8(buf,  0x001);
        buf_write_u8(buf,  4);/* length of the vendor specified field */
        buf_write_u32(buf, 0x002);
    }
    return !error;
}

static void
fork_dhcp_action(struct tuntap *tt)
{
    if (tt->options.dhcp_pre_release || tt->options.dhcp_renew)
    {
        struct gc_arena gc = gc_new();
        struct buffer cmd = alloc_buf_gc(256, &gc);
        const int verb = 3;
        const int pre_sleep = 1;

        buf_printf(&cmd, "openvpn --verb %d --tap-sleep %d", verb, pre_sleep);
        if (tt->options.dhcp_pre_release)
        {
            buf_printf(&cmd, " --dhcp-pre-release");
        }
        if (tt->options.dhcp_renew)
        {
            buf_printf(&cmd, " --dhcp-renew");
        }
        buf_printf(&cmd, " --dhcp-internal %lu", tt->adapter_index);

        fork_to_self(BSTR(&cmd));
        gc_free(&gc);
    }
}

static void
register_dns_service(const struct tuntap *tt)
{
    HANDLE msg_channel = tt->options.msg_channel;
    ack_message_t ack;
    struct gc_arena gc = gc_new();

    message_header_t rdns = { msg_register_dns, sizeof(message_header_t), 0 };

    if (!send_msg_iservice(msg_channel, &rdns, sizeof(rdns), &ack, "Register_dns"))
    {
        gc_free(&gc);
        return;
    }

    else if (ack.error_number != NO_ERROR)
    {
        msg(M_WARN, "Register_dns failed using service: %s [status=0x%x]",
            strerror_win32(ack.error_number, &gc), ack.error_number);
    }

    else
    {
        msg(M_INFO, "Register_dns request sent to the service");
    }

    gc_free(&gc);
}

static bool
service_register_ring_buffers(const struct tuntap *tt)
{
    HANDLE msg_channel = tt->options.msg_channel;
    ack_message_t ack;
    bool ret = true;
    struct gc_arena gc = gc_new();

    register_ring_buffers_message_t msg = {
        .header = {
            msg_register_ring_buffers,
            sizeof(register_ring_buffers_message_t),
            0
        },
        .device = tt->hand,
        .send_ring_handle = tt->wintun_send_ring_handle,
        .receive_ring_handle = tt->wintun_receive_ring_handle,
        .send_tail_moved = tt->rw_handle.read,
        .receive_tail_moved = tt->rw_handle.write
    };

    if (!send_msg_iservice(msg_channel, &msg, sizeof(msg), &ack, "Register ring buffers"))
    {
        ret = false;
    }
    else if (ack.error_number != NO_ERROR)
    {
        msg(M_NONFATAL, "Register ring buffers failed using service: %s [status=0x%x]",
            strerror_win32(ack.error_number, &gc), ack.error_number);
        ret = false;
    }
    else
    {
        msg(M_INFO, "Ring buffers registered via service");
    }

    gc_free(&gc);
    return ret;
}

void
fork_register_dns_action(struct tuntap *tt)
{
    if (tt && tt->options.register_dns && tt->options.msg_channel)
    {
        register_dns_service(tt);
    }
    else if (tt && tt->options.register_dns)
    {
        struct gc_arena gc = gc_new();
        struct buffer cmd = alloc_buf_gc(256, &gc);
        const int verb = 3;

        buf_printf(&cmd, "openvpn --verb %d --register-dns --rdns-internal", verb);
        fork_to_self(BSTR(&cmd));
        gc_free(&gc);
    }
}

static uint32_t
dhcp_masq_addr(const in_addr_t local, const in_addr_t netmask, const int offset)
{
    struct gc_arena gc = gc_new();
    in_addr_t dsa; /* DHCP server addr */

    if (offset < 0)
    {
        dsa = (local | (~netmask)) + offset;
    }
    else
    {
        dsa = (local & netmask) + offset;
    }

    if (dsa == local)
    {
        msg(M_FATAL, "ERROR: There is a clash between the --ifconfig local address and the internal DHCP server address -- both are set to %s -- please use the --ip-win32 dynamic option to choose a different free address from the --ifconfig subnet for the internal DHCP server", print_in_addr_t(dsa, 0, &gc));
    }

    if ((local & netmask) != (dsa & netmask))
    {
        msg(M_FATAL, "ERROR: --ip-win32 dynamic [offset] : offset is outside of --ifconfig subnet");
    }

    gc_free(&gc);
    return htonl(dsa);
}

static void
tuntap_get_version_info(const struct tuntap *tt)
{
    ULONG info[3];
    DWORD len;
    CLEAR(info);
    if (DeviceIoControl(tt->hand, TAP_WIN_IOCTL_GET_VERSION,
                        &info, sizeof(info),
                        &info, sizeof(info), &len, NULL))
    {
        msg(D_TUNTAP_INFO, "TAP-Windows Driver Version %d.%d %s",
            (int)info[0],
            (int)info[1],
            (info[2] ? "(DEBUG)" : ""));

    }
    if (!(info[0] == TAP_WIN_MIN_MAJOR && info[1] >= TAP_WIN_MIN_MINOR))
    {
        msg(M_FATAL, "ERROR:  This version of " PACKAGE_NAME " requires a TAP-Windows driver that is at least version %d.%d -- If you recently upgraded your " PACKAGE_NAME " distribution, a reboot is probably required at this point to get Windows to see the new driver.",
            TAP_WIN_MIN_MAJOR,
            TAP_WIN_MIN_MINOR);
    }

    /* usage of numeric constants is ugly, but this is really tied to
     * *this* version of the driver
     */
    if (tt->type == DEV_TYPE_TUN
        && info[0] == 9 && info[1] < 8)
    {
        msg(M_INFO, "WARNING:  Tap-Win32 driver version %d.%d does not support IPv6 in TUN mode. IPv6 will not work. Upgrade your Tap-Win32 driver.", (int)info[0], (int)info[1]);
    }

    /* tap driver 9.8 (2.2.0 and 2.2.1 release) is buggy
     */
    if (tt->type == DEV_TYPE_TUN
        && info[0] == 9 && info[1] == 8)
    {
        msg(M_FATAL, "ERROR:  Tap-Win32 driver version %d.%d is buggy regarding small IPv4 packets in TUN mode. Upgrade your Tap-Win32 driver.", (int)info[0], (int)info[1]);
    }
}

static void
tuntap_get_mtu(struct tuntap *tt)
{
    ULONG mtu = 0;
    DWORD len;
    if (DeviceIoControl(tt->hand, TAP_WIN_IOCTL_GET_MTU,
                        &mtu, sizeof(mtu),
                        &mtu, sizeof(mtu), &len, NULL))
    {
        msg(D_MTU_INFO, "TAP-Windows MTU=%d", (int)mtu);
    }
}

static void
tuntap_set_ip_addr(struct tuntap *tt,
                   const char *device_guid,
                   bool dhcp_masq_post)
{
    struct gc_arena gc = gc_new();
    const DWORD index = tt->adapter_index;

    /* flush arp cache */
    if (tt->windows_driver == WINDOWS_DRIVER_TAP_WINDOWS6
        && index != TUN_ADAPTER_INDEX_INVALID)
    {
        DWORD status = -1;

        if (tt->options.msg_channel)
        {
            ack_message_t ack;
            flush_neighbors_message_t msg = {
                .header = {
                    msg_flush_neighbors,
                    sizeof(flush_neighbors_message_t),
                    0
                },
                .family = AF_INET,
                .iface = {.index = index, .name = "" }
            };

            if (send_msg_iservice(tt->options.msg_channel, &msg, sizeof(msg),
                                  &ack, "TUN"))
            {
                status = ack.error_number;
            }
        }
        else
        {
            status = FlushIpNetTable(index);
        }

        if (status == NO_ERROR)
        {
            msg(M_INFO, "Successful ARP Flush on interface [%lu] %s",
                index,
                device_guid);
        }
        else if (status != -1)
        {
            msg(D_TUNTAP_INFO, "NOTE: FlushIpNetTable failed on interface [%lu] %s (status=%lu) : %s",
                index,
                device_guid,
                status,
                strerror_win32(status, &gc));
        }

        /*
         * If the TAP-Windows driver is masquerading as a DHCP server
         * make sure the TCP/IP properties for the adapter are
         * set correctly.
         */
        if (dhcp_masq_post)
        {
            /* check dhcp enable status */
            if (dhcp_status(index) == DHCP_STATUS_DISABLED)
            {
                msg(M_WARN, "WARNING: You have selected '--ip-win32 dynamic', which will not work unless the TAP-Windows TCP/IP properties are set to 'Obtain an IP address automatically'");
            }

            /* force an explicit DHCP lease renewal on TAP adapter? */
            if (tt->options.dhcp_pre_release)
            {
                dhcp_release(tt);
            }
            if (tt->options.dhcp_renew)
            {
                dhcp_renew(tt);
            }
        }
        else
        {
            fork_dhcp_action(tt);
        }
    }

    if (tt->did_ifconfig_setup && tt->options.ip_win32_type == IPW32_SET_IPAPI)
    {
        DWORD status;
        const char *error_suffix = "I am having trouble using the Windows 'IP helper API' to automatically set the IP address -- consider using other --ip-win32 methods (not 'ipapi')";

        /* couldn't get adapter index */
        if (index == TUN_ADAPTER_INDEX_INVALID)
        {
            msg(M_FATAL, "ERROR: unable to get adapter index for interface %s -- %s",
                device_guid,
                error_suffix);
        }

        /* check dhcp enable status */
        if (dhcp_status(index) == DHCP_STATUS_DISABLED)
        {
            msg(M_WARN, "NOTE: You have selected (explicitly or by default) '--ip-win32 ipapi', which has a better chance of working correctly if the TAP-Windows TCP/IP properties are set to 'Obtain an IP address automatically'");
        }

        /* delete previously added IP addresses which were not
         * correctly deleted */
        delete_temp_addresses(index);

        /* add a new IP address */
        if ((status = AddIPAddress(htonl(tt->local),
                                   htonl(tt->adapter_netmask),
                                   index,
                                   &tt->ipapi_context,
                                   &tt->ipapi_instance)) == NO_ERROR)
        {
            msg(M_INFO, "Succeeded in adding a temporary IP/netmask of %s/%s to interface %s using the Win32 IP Helper API",
                print_in_addr_t(tt->local, 0, &gc),
                print_in_addr_t(tt->adapter_netmask, 0, &gc),
                device_guid
                );
        }
        else
        {
            msg(M_FATAL, "ERROR: AddIPAddress %s/%s failed on interface %s, index=%lu, status=%lu (windows error: '%s') -- %s",
                print_in_addr_t(tt->local, 0, &gc),
                print_in_addr_t(tt->adapter_netmask, 0, &gc),
                device_guid,
                index,
                status,
                strerror_win32(status, &gc),
                error_suffix);
        }
        tt->ipapi_context_defined = true;
    }

    gc_free(&gc);
}

static bool
wintun_register_ring_buffer(struct tuntap *tt, const char *device_guid)
{
    bool ret = true;

    tt->wintun_send_ring = (struct tun_ring *)MapViewOfFile(tt->wintun_send_ring_handle,
                                                            FILE_MAP_ALL_ACCESS,
                                                            0,
                                                            0,
                                                            sizeof(struct tun_ring));

    tt->wintun_receive_ring = (struct tun_ring *)MapViewOfFile(tt->wintun_receive_ring_handle,
                                                               FILE_MAP_ALL_ACCESS,
                                                               0,
                                                               0,
                                                               sizeof(struct tun_ring));

    if (tt->options.msg_channel)
    {
        ret = service_register_ring_buffers(tt);
    }
    else
    {
        if (!register_ring_buffers(tt->hand,
                                   tt->wintun_send_ring,
                                   tt->wintun_receive_ring,
                                   tt->rw_handle.read,
                                   tt->rw_handle.write))
        {
            switch (GetLastError())
            {
                case ERROR_ACCESS_DENIED:
                    msg(M_FATAL, "ERROR:  Wintun requires SYSTEM privileges and therefore "
                        "should be used with interactive service. If you want to "
                        "use openvpn from command line, you need to do SYSTEM "
                        "elevation yourself (for example with psexec).");
                    break;

                case ERROR_ALREADY_INITIALIZED:
                    msg(M_NONFATAL, "Adapter %s is already in use", device_guid);
                    break;

                default:
                    msg(M_NONFATAL | M_ERRNO, "Failed to register ring buffers");
            }
            ret = false;
        }

    }
    return ret;
}

static void
tuntap_set_connected(const struct tuntap *tt)
{
    ULONG status = TRUE;
    DWORD len;
    if (!DeviceIoControl(tt->hand, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                         &status, sizeof(status),
                         &status, sizeof(status), &len, NULL))
    {
        msg(M_WARN, "WARNING: The TAP-Windows driver rejected a TAP_WIN_IOCTL_SET_MEDIA_STATUS DeviceIoControl call.");
    }

    int s = tt->options.tap_sleep;
    if (s > 0)
    {
        msg(M_INFO, "Sleeping for %d seconds...", s);
        management_sleep(s);
    }
}

static void
tuntap_set_ptp(const struct tuntap *tt)
{
    DWORD len;
    struct gc_arena gc = gc_new();

    if (!tt->did_ifconfig_setup && !tt->did_ifconfig_ipv6_setup)
    {
        msg(M_FATAL, "ERROR: --dev tun also requires --ifconfig");
    }

    /* send 0/0/0 to the TAP driver even if we have no IPv4 configured to
     * ensure it is somehow initialized.
     */
    if (!tt->did_ifconfig_setup || tt->topology == TOP_SUBNET)
    {
        in_addr_t ep[3];
        BOOL status;

        ep[0] = htonl(tt->local);
        ep[1] = htonl(tt->local & tt->remote_netmask);
        ep[2] = htonl(tt->remote_netmask);

        status = DeviceIoControl(tt->hand, TAP_WIN_IOCTL_CONFIG_TUN,
                                 ep, sizeof(ep),
                                 ep, sizeof(ep), &len, NULL);

        if (tt->did_ifconfig_setup)
        {
            msg(status ? M_INFO : M_FATAL, "Set TAP-Windows TUN subnet mode network/local/netmask = %s/%s/%s [%s]",
                print_in_addr_t(ep[1], IA_NET_ORDER, &gc),
                print_in_addr_t(ep[0], IA_NET_ORDER, &gc),
                print_in_addr_t(ep[2], IA_NET_ORDER, &gc),
                status ? "SUCCEEDED" : "FAILED");
        }
        else
        {
            msg(status ? M_INFO : M_FATAL, "Set TAP-Windows TUN with fake IPv4 [%s]",
                status ? "SUCCEEDED" : "FAILED");
        }
    }
    else
    {
        in_addr_t ep[2];
        ep[0] = htonl(tt->local);
        ep[1] = htonl(tt->remote_netmask);

        if (!DeviceIoControl(tt->hand, TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT,
                             ep, sizeof(ep),
                             ep, sizeof(ep), &len, NULL))
        {
            msg(M_FATAL, "ERROR: The TAP-Windows driver rejected a DeviceIoControl call to set Point-to-Point mode, which is required for --dev tun");
        }
    }

    gc_free(&gc);
}

static void
tuntap_dhcp_mask(const struct tuntap *tt, const char *device_guid)
{
    struct gc_arena gc = gc_new();
    DWORD len;
    uint32_t ep[4];

    /* We will answer DHCP requests with a reply to set IP/subnet to these values */
    ep[0] = htonl(tt->local);
    ep[1] = htonl(tt->adapter_netmask);

    /* At what IP address should the DHCP server masquerade at? */
    if (tt->type == DEV_TYPE_TUN)
    {
        if (tt->topology == TOP_SUBNET)
        {
            ep[2] = dhcp_masq_addr(tt->local, tt->remote_netmask, tt->options.dhcp_masq_custom_offset ? tt->options.dhcp_masq_offset : 0);
        }
        else
        {
            ep[2] = htonl(tt->remote_netmask);
        }
    }
    else
    {
        ASSERT(tt->type == DEV_TYPE_TAP);
        ep[2] = dhcp_masq_addr(tt->local, tt->adapter_netmask, tt->options.dhcp_masq_custom_offset ? tt->options.dhcp_masq_offset : 0);
    }

    /* lease time in seconds */
    ep[3] = (uint32_t)tt->options.dhcp_lease_time;

    ASSERT(ep[3] > 0);

#ifndef SIMULATE_DHCP_FAILED /* this code is disabled to simulate bad DHCP negotiation */
    if (!DeviceIoControl(tt->hand, TAP_WIN_IOCTL_CONFIG_DHCP_MASQ,
                         ep, sizeof(ep),
                         ep, sizeof(ep), &len, NULL))
    {
        msg(M_FATAL, "ERROR: The TAP-Windows driver rejected a DeviceIoControl call to set TAP_WIN_IOCTL_CONFIG_DHCP_MASQ mode");
    }

    msg(M_INFO, "Notified TAP-Windows driver to set a DHCP IP/netmask of %s/%s on interface %s [DHCP-serv: %s, lease-time: %d]",
        print_in_addr_t(tt->local, 0, &gc),
        print_in_addr_t(tt->adapter_netmask, 0, &gc),
        device_guid,
        print_in_addr_t(ep[2], IA_NET_ORDER, &gc),
        ep[3]
        );

    /* user-supplied DHCP options capability */
    if (tt->options.dhcp_options)
    {
        struct buffer buf = alloc_buf(256);
        if (build_dhcp_options_string(&buf, &tt->options))
        {
            msg(D_DHCP_OPT, "DHCP option string: %s", format_hex(BPTR(&buf), BLEN(&buf), 0, &gc));
            if (!DeviceIoControl(tt->hand, TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT,
                                 BPTR(&buf), BLEN(&buf),
                                 BPTR(&buf), BLEN(&buf), &len, NULL))
            {
                msg(M_FATAL, "ERROR: The TAP-Windows driver rejected a TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT DeviceIoControl call");
            }
        }
        else
        {
            msg(M_WARN, "DHCP option string not set due to error");
        }
        free_buf(&buf);
    }
#endif /* ifndef SIMULATE_DHCP_FAILED */

    gc_free(&gc);
}

static bool
tun_try_open_device(struct tuntap *tt, const char *device_guid, const struct device_instance_id_interface *device_instance_id_interface)
{
    const char *path = NULL;
    char tuntap_device_path[256];

    if (tt->windows_driver == WINDOWS_DRIVER_WINTUN
        || tt->windows_driver == WINDOWS_DRIVER_DCO)
    {
        const struct device_instance_id_interface *dev_if;

        for (dev_if = device_instance_id_interface; dev_if != NULL; dev_if = dev_if->next)
        {
            if (strcmp((const char *)dev_if->net_cfg_instance_id, device_guid) != 0)
            {
                continue;
            }

            if (tt->windows_driver == WINDOWS_DRIVER_DCO)
            {
                char *last_sep = strrchr(dev_if->device_interface, '\\');
                if (!last_sep
                    || strcmp(last_sep + 1, DCO_WIN_REFERENCE_STRING) != 0)
                {
                    continue;
                }
            }

            path = dev_if->device_interface;
            break;
        }
        if (path == NULL)
        {
            return false;
        }
    }
    else
    {
        /* Open TAP-Windows */
        openvpn_snprintf(tuntap_device_path, sizeof(tuntap_device_path), "%s%s%s",
                         USERMODEDEVICEDIR,
                         device_guid,
                         TAP_WIN_SUFFIX);
        path = tuntap_device_path;
    }

    msg(D_TAP_WIN_DEBUG, "Using device interface: %s", path);

    tt->hand = CreateFile(path,
                          GENERIC_READ | GENERIC_WRITE,
                          0,         /* was: FILE_SHARE_READ */
                          0,
                          OPEN_EXISTING,
                          FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                          0);
    if (tt->hand == INVALID_HANDLE_VALUE)
    {
        msg(D_TUNTAP_INFO | M_ERRNO, "CreateFile failed on %s device: %s", print_windows_driver(tt->windows_driver), path);
        return false;
    }

    if (tt->windows_driver == WINDOWS_DRIVER_WINTUN)
    {
        /* Wintun adapter may be considered "open" after ring buffers are successfuly registered. */
        if (!wintun_register_ring_buffer(tt, device_guid))
        {
            msg(D_TUNTAP_INFO, "Failed to register %s adapter ring buffers", device_guid);
            CloseHandle(tt->hand);
            tt->hand = NULL;
            return false;
        }
    }

    return true;
}

void
tun_open_device(struct tuntap *tt, const char *dev_node, const char **device_guid, struct gc_arena *gc)
{
    const struct tap_reg *tap_reg = get_tap_reg(gc);
    const struct panel_reg *panel_reg = get_panel_reg(gc);
    const struct device_instance_id_interface *device_instance_id_interface = get_device_instance_id_interface(gc);
    uint8_t actual_buffer[256];

    at_least_one_tap_win(tap_reg);

    /*
     * Lookup the device name in the registry, using the --dev-node high level name.
     */
    if (dev_node)
    {
        enum windows_driver_type windows_driver = WINDOWS_DRIVER_UNSPECIFIED;

        /* Get the device GUID for the device specified with --dev-node. */
        *device_guid = get_device_guid(dev_node, actual_buffer, sizeof(actual_buffer), &windows_driver, tap_reg, panel_reg, gc);

        if (!*device_guid)
        {
            msg(M_FATAL, "Adapter '%s' not found", dev_node);
        }

        if (tt->windows_driver != windows_driver)
        {
            msg(M_FATAL, "Adapter '%s' is using %s driver, %s expected. If you want to use this device, adjust --windows-driver.",
                dev_node, print_windows_driver(windows_driver), print_windows_driver(tt->windows_driver));
        }

        if (!tun_try_open_device(tt, *device_guid, device_instance_id_interface))
        {
            msg(M_FATAL, "Failed to open %s adapter: %s", print_windows_driver(tt->windows_driver), dev_node);
        }
    }
    else
    {
        int device_number = 0;

        /* Try opening all TAP devices until we find one available */
        while (true)
        {
            enum windows_driver_type windows_driver = WINDOWS_DRIVER_UNSPECIFIED;
            *device_guid = get_unspecified_device_guid(device_number,
                                                       actual_buffer,
                                                       sizeof(actual_buffer),
                                                       tap_reg,
                                                       panel_reg,
                                                       &windows_driver,
                                                       gc);

            if (!*device_guid)
            {
                msg(M_FATAL, "All %s adapters on this system are currently in use or disabled.", print_windows_driver(tt->windows_driver));
            }

            if (tt->windows_driver != windows_driver)
            {
                goto next;
            }

            if (tun_try_open_device(tt, *device_guid, device_instance_id_interface))
            {
                break;
            }

next:
            device_number++;
        }
    }

    /* translate high-level device name into a device instance
     * GUID using the registry */
    tt->actual_name = string_alloc((const char *)actual_buffer, NULL);

    msg(M_INFO, "%s device [%s] opened", print_windows_driver(tt->windows_driver), tt->actual_name);
    tt->adapter_index = get_adapter_index(*device_guid);
}

static void
tuntap_set_ip_props(const struct tuntap *tt, bool *dhcp_masq, bool *dhcp_masq_post)
{
    if (tt->options.ip_win32_type == IPW32_SET_DHCP_MASQ)
    {
        /*
         * If adapter is set to non-DHCP, set to DHCP mode.
         */
        if (dhcp_status(tt->adapter_index) == DHCP_STATUS_DISABLED)
        {
            /* try using the service if available, else directly execute netsh */
            if (tt->options.msg_channel)
            {
                service_enable_dhcp(tt);
            }
            else
            {
                netsh_enable_dhcp(tt->adapter_index);
            }
        }
        *dhcp_masq = true;
        *dhcp_masq_post = true;
    }
    else if (tt->options.ip_win32_type == IPW32_SET_ADAPTIVE)
    {
        /*
         * If adapter is set to non-DHCP, use netsh right away.
         */
        if (dhcp_status(tt->adapter_index) != DHCP_STATUS_ENABLED)
        {
            netsh_ifconfig(&tt->options,
                           tt->adapter_index,
                           tt->local,
                           tt->adapter_netmask,
                           NI_TEST_FIRST | NI_IP_NETMASK | NI_OPTIONS);
        }
        else
        {
            *dhcp_masq = true;
        }
    }
}

static void
tuntap_post_open(struct tuntap *tt, const char *device_guid)
{
    bool dhcp_masq = false;
    bool dhcp_masq_post = false;

    if (tt->windows_driver == WINDOWS_DRIVER_TAP_WINDOWS6)
    {
        /* get driver version info */
        tuntap_get_version_info(tt);

        /* get driver MTU */
        tuntap_get_mtu(tt);

        /*
         * Preliminaries for setting TAP-Windows adapter TCP/IP
         * properties via --ip-win32 dynamic or --ip-win32 adaptive.
         */
        if (tt->did_ifconfig_setup)
        {
            tuntap_set_ip_props(tt, &dhcp_masq, &dhcp_masq_post);
        }

        /* set point-to-point mode if TUN device */
        if (tt->type == DEV_TYPE_TUN)
        {
            tuntap_set_ptp(tt);
        }

        /* should we tell the TAP-Windows driver to masquerade as a DHCP server as a means
         * of setting the adapter address? */
        if (dhcp_masq)
        {
            tuntap_dhcp_mask(tt, device_guid);
        }

        /* set driver media status to 'connected' */
        tuntap_set_connected(tt);
    }

    /* possibly use IP Helper API to set IP address on adapter */
    tuntap_set_ip_addr(tt, device_guid, dhcp_masq_post);
}

void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
    if ((tt->options.dhcp_options & DHCP_OPTIONS_DHCP_REQUIRED)
        && tt->windows_driver != WINDOWS_DRIVER_TAP_WINDOWS6)
    {
        msg(M_WARN, "Some --dhcp-option or --dns options require DHCP server,"
            " which is not supported by the selected %s driver. They will be"
            " ignored.", print_windows_driver(tt->windows_driver));
    }

    /* dco-win already opened the device, which handle we treat as socket */
    if (tuntap_is_dco_win(tt))
    {
        return;
    }

    const char *device_guid = NULL;

    /*netcmd_semaphore_lock ();*/

    msg( M_INFO, "open_tun");

    if (tt->type == DEV_TYPE_NULL)
    {
        open_null(tt);
        return;
    }
    else if (tt->type != DEV_TYPE_TAP && tt->type != DEV_TYPE_TUN)
    {
        msg(M_FATAL|M_NOPREFIX, "Unknown virtual device type: '%s'", dev);
    }

    struct gc_arena gc = gc_new(); /* used also for device_guid allocation */
    tun_open_device(tt, dev_node, &device_guid, &gc);

    tuntap_post_open(tt, device_guid);

    gc_free(&gc);

    /*netcmd_semaphore_release ();*/
}

const char *
tap_win_getinfo(const struct tuntap *tt, struct gc_arena *gc)
{
    if (tt->windows_driver == WINDOWS_DRIVER_TAP_WINDOWS6)
    {
        struct buffer out = alloc_buf_gc(256, gc);
        DWORD len;
        if (DeviceIoControl(tt->hand, TAP_WIN_IOCTL_GET_INFO,
                            BSTR(&out), BCAP(&out),
                            BSTR(&out), BCAP(&out),
                            &len, NULL))
        {
            return BSTR(&out);
        }
    }
    return NULL;
}

void
tun_show_debug(struct tuntap *tt)
{
    if (tt->windows_driver == WINDOWS_DRIVER_TAP_WINDOWS6)
    {
        struct buffer out = alloc_buf(1024);
        DWORD len;
        while (DeviceIoControl(tt->hand, TAP_WIN_IOCTL_GET_LOG_LINE,
                               BSTR(&out), BCAP(&out),
                               BSTR(&out), BCAP(&out),
                               &len, NULL))
        {
            msg(D_TAP_WIN_DEBUG, "TAP-Windows: %s", BSTR(&out));
        }
        free_buf(&out);
    }
}

static void
netsh_delete_address_dns(const struct tuntap *tt, bool ipv6, struct gc_arena *gc)
{
    const char *ifconfig_ip_local;
    struct argv argv = argv_new();

    /* delete ipvX dns servers if any were set */
    int len = ipv6 ? tt->options.dns6_len : tt->options.dns_len;
    if (len > 0)
    {
        argv_printf(&argv,
                    "%s%s interface %s delete dns %lu all",
                    get_win_sys_path(),
                    NETSH_PATH_SUFFIX,
                    ipv6 ? "ipv6" : "ipv4",
                    tt->adapter_index);
        netsh_command(&argv, 1, M_WARN);
    }

    if (!ipv6 && tt->options.wins_len > 0)
    {
        argv_printf(&argv,
                    "%s%s interface ipv4 delete winsservers %lu all",
                    get_win_sys_path(),
                    NETSH_PATH_SUFFIX,
                    tt->adapter_index);
        netsh_command(&argv, 1, M_WARN);
    }

    if (ipv6 && tt->type == DEV_TYPE_TUN)
    {
        delete_route_connected_v6_net(tt);
    }

    /* "store=active" is needed in Windows 8(.1) to delete the
     * address we added (pointed out by Cedric Tabary).
     */

    /* netsh interface ipvX delete address %lu %s */
    if (ipv6)
    {
        ifconfig_ip_local = print_in6_addr(tt->local_ipv6, 0, gc);
    }
    else
    {
        ifconfig_ip_local = print_in_addr_t(tt->local, 0, gc);
    }
    argv_printf(&argv,
                "%s%s interface %s delete address %lu %s store=active",
                get_win_sys_path(),
                NETSH_PATH_SUFFIX,
                ipv6 ? "ipv6" : "ipv4",
                tt->adapter_index,
                ifconfig_ip_local);
    netsh_command(&argv, 1, M_WARN);

    argv_free(&argv);
}

void
close_tun_handle(struct tuntap *tt)
{
    const char *adaptertype = print_windows_driver(tt->windows_driver);

    if (tt->hand)
    {
        dmsg(D_WIN32_IO_LOW, "Attempting CancelIO on %s adapter", adaptertype);
        if (!CancelIo(tt->hand))
        {
            msg(M_WARN | M_ERRNO, "Warning: CancelIO failed on %s adapter", adaptertype);
        }
    }

    dmsg(D_WIN32_IO_LOW, "Attempting close of overlapped read event on %s adapter", adaptertype);
    overlapped_io_close(&tt->reads);

    dmsg(D_WIN32_IO_LOW, "Attempting close of overlapped write event on %s adapter", adaptertype);
    overlapped_io_close(&tt->writes);

    if (tt->hand)
    {
        dmsg(D_WIN32_IO_LOW, "Attempting CloseHandle on %s adapter", adaptertype);
        if (!CloseHandle(tt->hand))
        {
            msg(M_WARN | M_ERRNO, "Warning: CloseHandle failed on %s adapter", adaptertype);
        }
        tt->hand = NULL;
    }

    if (tt->windows_driver == WINDOWS_DRIVER_WINTUN)
    {
        CloseHandle(tt->rw_handle.read);
        CloseHandle(tt->rw_handle.write);
        UnmapViewOfFile(tt->wintun_send_ring);
        UnmapViewOfFile(tt->wintun_receive_ring);
        CloseHandle(tt->wintun_send_ring_handle);
        CloseHandle(tt->wintun_receive_ring_handle);
    }
}

void
close_tun(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    ASSERT(tt);

    struct gc_arena gc = gc_new();

    if (tt->did_ifconfig_ipv6_setup)
    {
        if (tt->options.ip_win32_type == IPW32_SET_MANUAL)
        {
            /* We didn't do ifconfig. */
        }
        else if (tt->options.msg_channel)
        {
            /* If IPv4 is not enabled, delete DNS domain here */
            if (!tt->did_ifconfig_setup)
            {
                do_dns_domain_service(false, tt);
            }
            do_dns_service(false, AF_INET6, tt);
            delete_route_connected_v6_net(tt);
            do_address_service(false, AF_INET6, tt);
        }
        else
        {
            if (!tt->did_ifconfig_setup)
            {
                do_dns_domain_wmic(false, tt);
            }

            netsh_delete_address_dns(tt, true, &gc);
        }
    }

    if (tt->did_ifconfig_setup)
    {
        if (tt->options.ip_win32_type == IPW32_SET_MANUAL)
        {
            /* We didn't do ifconfig. */
        }
        else if (tt->options.ip_win32_type == IPW32_SET_DHCP_MASQ || tt->options.ip_win32_type == IPW32_SET_ADAPTIVE)
        {
            /* We don't have to clean the configuration with DHCP. */
        }
        else if (tt->options.msg_channel)
        {
            do_wins_service(false, tt);
            do_dns_domain_service(false, tt);
            do_dns_service(false, AF_INET, tt);
            do_address_service(false, AF_INET, tt);
        }
        else
        {
            do_dns_domain_wmic(false, tt);

            if (tt->options.ip_win32_type == IPW32_SET_NETSH)
            {
                netsh_delete_address_dns(tt, false, &gc);
            }
        }
    }

    if (tt->ipapi_context_defined)
    {
        DWORD status;
        if ((status = DeleteIPAddress(tt->ipapi_context)) != NO_ERROR)
        {
            msg(M_WARN, "Warning: DeleteIPAddress[%u] failed on TAP-Windows adapter, status=%u : %s",
                (unsigned int)tt->ipapi_context,
                (unsigned int)status,
                strerror_win32(status, &gc));
        }
    }

    dhcp_release(tt);

    close_tun_handle(tt);

    free(tt->actual_name);

    clear_tuntap(tt);
    free(tt);
    gc_free(&gc);
}

/*
 * Convert --ip-win32 constants between index and ascii form.
 */

struct ipset_names {
    const char *short_form;
};

/* Indexed by IPW32_SET_x */
static const struct ipset_names ipset_names[] = {
    {"manual"},
    {"netsh"},
    {"ipapi"},
    {"dynamic"},
    {"adaptive"}
};

int
ascii2ipset(const char *name)
{
    int i;
    ASSERT(IPW32_SET_N == SIZE(ipset_names));
    for (i = 0; i < IPW32_SET_N; ++i)
    {
        if (!strcmp(name, ipset_names[i].short_form))
        {
            return i;
        }
    }
    return -1;
}

const char *
ipset2ascii(int index)
{
    ASSERT(IPW32_SET_N == SIZE(ipset_names));
    if (index < 0 || index >= IPW32_SET_N)
    {
        return "[unknown --ip-win32 type]";
    }
    else
    {
        return ipset_names[index].short_form;
    }
}

const char *
ipset2ascii_all(struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);
    int i;

    ASSERT(IPW32_SET_N == SIZE(ipset_names));
    for (i = 0; i < IPW32_SET_N; ++i)
    {
        if (i)
        {
            buf_printf(&out, " ");
        }
        buf_printf(&out, "[%s]", ipset2ascii(i));
    }
    return BSTR(&out);
}

const char *
print_windows_driver(enum windows_driver_type windows_driver)
{
    switch (windows_driver)
    {
        case WINDOWS_DRIVER_TAP_WINDOWS6:
            return "tap-windows6";

        case WINDOWS_DRIVER_WINTUN:
            return "wintun";

        case WINDOWS_DRIVER_DCO:
            return "ovpn-dco";

        default:
            return "unspecified";
    }
}

#else /* generic */

void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
    open_tun_generic(dev, dev_type, dev_node, tt);
}

void
close_tun(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    ASSERT(tt);

    close_tun_generic(tt);
    free(tt);
}

int
write_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    return write(tt->fd, buf, len);
}

int
read_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    return read(tt->fd, buf, len);
}

#endif /* if defined (TARGET_ANDROID) */
