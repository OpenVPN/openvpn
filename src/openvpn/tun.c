/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
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
#include "socket_util.h"
#include "manage.h"
#include "route.h"
#include "win32.h"
#include "wfp_block.h"
#include "networking.h"
#include "dhcp.h"

#include "memdbg.h"

#include <string.h>

const char *
print_tun_backend_driver(enum tun_driver_type driver)
{
    switch (driver)
    {
        case WINDOWS_DRIVER_TAP_WINDOWS6:
            return "tap-windows6";

        case DRIVER_GENERIC_TUNTAP:
            return "tun/tap";

        case DRIVER_DCO:
            return "ovpn-dco";

        case DRIVER_AFUNIX:
            return "unix";

        case DRIVER_NULL:
            return "null";

        case DRIVER_UTUN:
            return "utun";

        default:
            return "unspecified";
    }
}

#ifdef TARGET_SOLARIS
static void solaris_error_close(struct tuntap *tt, const struct env_set *es, const char *actual,
                                bool unplumb_inet6);

#include <stropts.h>
#endif

#if defined(TARGET_DARWIN)
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
    /* We pretend that the null device is also a tun device but it does not
     * really matter as it will discard everything anyway */
    if (is_dev_type(dev, dev_type, "tun") || is_dev_type(dev, dev_type, "null"))
    {
        return DEV_TYPE_TUN;
    }
    else if (is_dev_type(dev, dev_type, "tap"))
    {
        return DEV_TYPE_TAP;
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

        default:
            return "[unknown-dev-type]";
    }
}

/*
 * Try to predict the actual TUN/TAP device instance name,
 * before the device is actually opened.
 */
const char *
guess_tuntap_dev(const char *dev, const char *dev_type, const char *dev_node, struct gc_arena *gc)
{
    /* default case */
    return dev;
}


/* --ifconfig-nowarn disables some options sanity checking */
static const char ifconfig_warn_how_to_silence[] = "(silence this warning with --ifconfig-nowarn)";

/*
 * If !tun_p2p, make sure ifconfig_remote_netmask looks
 *  like a netmask.
 *
 * If tun_p2p, make sure ifconfig_remote_netmask looks
 *  like an IPv4 address.
 */
static void
ifconfig_sanity_check(bool tun_p2p, in_addr_t addr)
{
    struct gc_arena gc = gc_new();
    const bool looks_like_netmask = ((addr & 0xFF000000) == 0xFF000000);
    if (tun_p2p)
    {
        if (looks_like_netmask)
        {
            msg(M_WARN,
                "WARNING: Since you are using --dev tun with a point-to-point topology, the second argument to --ifconfig must be an IP address.  You are using something (%s) that looks more like a netmask. %s",
                print_in_addr_t(addr, 0, &gc), ifconfig_warn_how_to_silence);
        }
    }
    else
    {
        if (!looks_like_netmask)
        {
            msg(M_WARN,
                "WARNING: Since you are using subnet topology, the second argument to --ifconfig must be a netmask, for example something like 255.255.255.0. %s",
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
check_addr_clash(const char *name, int type, in_addr_t public, in_addr_t local,
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
            const in_addr_t public_net = public & test_netmask;
            const in_addr_t local_net = local & test_netmask;
            const in_addr_t remote_net = remote_netmask & test_netmask;

            if (public == local || public == remote_netmask)
            {
                msg(M_WARN,
                    "WARNING: --%s address [%s] conflicts with --ifconfig address pair [%s, %s]. %s",
                    name, print_in_addr_t(public, 0, &gc), print_in_addr_t(local, 0, &gc),
                    print_in_addr_t(remote_netmask, 0, &gc), ifconfig_warn_how_to_silence);
            }

            if (public_net == local_net || public_net == remote_net)
            {
                msg(M_WARN,
                    "WARNING: potential conflict between --%s address [%s] and --ifconfig address pair [%s, %s] -- this is a warning only that is triggered when local/remote addresses exist within the same /24 subnet as --ifconfig endpoints. %s",
                    name, print_in_addr_t(public, 0, &gc), print_in_addr_t(local, 0, &gc),
                    print_in_addr_t(remote_netmask, 0, &gc), ifconfig_warn_how_to_silence);
            }
        }
        else if (type == DEV_TYPE_TAP)
        {
            const in_addr_t public_network = public & remote_netmask;
            const in_addr_t virtual_network = local & remote_netmask;
            if (public_network == virtual_network)
            {
                msg(M_WARN,
                    "WARNING: --%s address [%s] conflicts with --ifconfig subnet [%s, %s] -- local and remote addresses cannot be inside of the --ifconfig subnet. %s",
                    name, print_in_addr_t(public, 0, &gc), print_in_addr_t(local, 0, &gc),
                    print_in_addr_t(remote_netmask, 0, &gc), ifconfig_warn_how_to_silence);
            }
        }
    }
    gc_free(&gc);
}

void
warn_on_use_of_common_subnets(openvpn_net_ctx_t *ctx)
{
    struct gc_arena gc = gc_new();
    struct route_gateway_info rgi;
    const unsigned int needed = (RGI_ADDR_DEFINED | RGI_NETMASK_DEFINED);

    get_default_gateway(&rgi, 0, ctx);
    if ((rgi.flags & needed) == needed)
    {
        const in_addr_t lan_network = rgi.gateway.addr & rgi.gateway.netmask;
        if (lan_network == 0xC0A80000 || lan_network == 0xC0A80100)
        {
            msg(M_WARN,
                "NOTE: your local LAN uses the extremely common subnet address 192.168.0.x or 192.168.1.x.  Be aware that this might create routing conflicts if you connect to the VPN server from public locations such as internet cafes that use the same subnet.");
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
        if (!is_tun_p2p(tt))
        {
            buf_printf(&out, "%s %s", print_in_addr_t(tt->local & tt->remote_netmask, 0, gc),
                       print_in_addr_t(tt->remote_netmask, 0, gc));
        }
        else if (tt->type == DEV_TYPE_TUN) /* tun p2p topology */
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
            buf_printf(&out, "T%s", (tt->rwflags_debug & EVENT_READ) ? "R" : "r");
        }
        if (rwflags & EVENT_WRITE)
        {
            buf_printf(&out, "T%s", (tt->rwflags_debug & EVENT_WRITE) ? "W" : "w");
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
    bool tun_p2p = false;

    if (tt->type == DEV_TYPE_TAP || (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET))
    {
        tun_p2p = false;
    }
    else if (tt->type == DEV_TYPE_TUN)
    {
        tun_p2p = true;
    }
    else
    {
        msg(M_FATAL, "Error: problem with tun vs. tap setting"); /* JYFIXME -- needs to be caught
                                                                    earlier, in init_tun? */
    }
    return tun_p2p;
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
init_tun(const char *dev,                          /* --dev option */
         const char *dev_type,                     /* --dev-type option */
         int topology,                             /* one of the TOP_x values */
         const char *ifconfig_local_parm,          /* --ifconfig parm 1 */
         const char *ifconfig_remote_netmask_parm, /* --ifconfig parm 2 */
         const char *ifconfig_ipv6_local_parm,     /* --ifconfig parm 1 IPv6 */
         int ifconfig_ipv6_netbits_parm,
         const char *ifconfig_ipv6_remote_parm,    /* --ifconfig parm 2 IPv6 */
         struct addrinfo *local_public, struct addrinfo *remote_public, const bool strict_warn,
         struct env_set *es, openvpn_net_ctx_t *ctx, struct tuntap *tt)
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
        /*
         * We only handle TUN/TAP devices here, not --dev null devices.
         */
        bool tun_p2p = is_tun_p2p(tt);

        /*
         * Convert arguments to binary IPv4 addresses.
         */

        tt->local =
            getaddr(GETADDR_RESOLVE | GETADDR_HOST_ORDER | GETADDR_FATAL_ON_SIGNAL | GETADDR_FATAL,
                    ifconfig_local_parm, 0, NULL, NULL);

        tt->remote_netmask = getaddr((tun_p2p ? GETADDR_RESOLVE : 0) | GETADDR_HOST_ORDER
                                         | GETADDR_FATAL_ON_SIGNAL | GETADDR_FATAL,
                                     ifconfig_remote_netmask_parm, 0, NULL, NULL);

        /*
         * Look for common errors in --ifconfig parms
         */
        if (strict_warn)
        {
            struct addrinfo *curele;
            ifconfig_sanity_check(tun_p2p, tt->remote_netmask);

            /*
             * If local_public or remote_public addresses are defined,
             * make sure they do not clash with our virtual subnet.
             */

            for (curele = local_public; curele; curele = curele->ai_next)
            {
                if (curele->ai_family == AF_INET)
                {
                    const in_addr_t local =
                        ntohl(((struct sockaddr_in *)curele->ai_addr)->sin_addr.s_addr);
                    check_addr_clash("local", tt->type, local, tt->local, tt->remote_netmask);
                }
            }

            for (curele = remote_public; curele; curele = curele->ai_next)
            {
                if (curele->ai_family == AF_INET)
                {
                    const in_addr_t remote =
                        ntohl(((struct sockaddr_in *)curele->ai_addr)->sin_addr.s_addr);
                    check_addr_clash("remote", tt->type, remote, tt->local, tt->remote_netmask);
                }
            }
        }

        tt->did_ifconfig_setup = true;
    }

    if (ifconfig_ipv6_local_parm && ifconfig_ipv6_remote_parm)
    {
        /*
         * Convert arguments to binary IPv6 addresses.
         */

        if (inet_pton(AF_INET6, ifconfig_ipv6_local_parm, &tt->local_ipv6) != 1
            || inet_pton(AF_INET6, ifconfig_ipv6_remote_parm, &tt->remote_ipv6) != 1)
        {
            msg(M_FATAL, "init_tun: problem converting IPv6 ifconfig addresses %s and %s to binary",
                ifconfig_ipv6_local_parm, ifconfig_ipv6_remote_parm);
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
init_tun_post(struct tuntap *tt, const struct frame *frame, const struct tuntap_options *options)
{
    tt->options = *options;
}

#if defined(TARGET_FREEBSD) || defined(TARGET_DRAGONFLY) || defined(TARGET_NETBSD) \
    || defined(TARGET_OPENBSD)
/* we can't use true subnet mode on tun on all platforms, as that
 * conflicts with IPv6 (wants to use ND then, which we don't do),
 * but the OSes want "a remote address that is different from ours"
 * - so we construct one, normally the first in the subnet, but if
 * this is the same as ours, use the second one.
 * The actual address does not matter at all, as the tun interface
 * is still point to point and no layer 2 resolution is done...
 */

in_addr_t
create_arbitrary_remote(struct tuntap *tt)
{
    in_addr_t remote;

    remote = (tt->local & tt->remote_netmask) + 1;

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
 * @param tun_mtu   the MTU value to set the interface to
 * @param es        the environment to be used when executing the commands
 * @param ctx       the networking API opaque context
 */
static void
do_ifconfig_ipv6(struct tuntap *tt, const char *ifname, int tun_mtu, const struct env_set *es,
                 openvpn_net_ctx_t *ctx)
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

    if (net_addr_v6_add(ctx, ifname, &tt->local_ipv6, tt->netbits_ipv6) < 0)
    {
        msg(M_FATAL, "Linux can't add IPv6 to interface %s", ifname);
    }
#elif defined(TARGET_ANDROID)
    char out6[64];

    snprintf(out6, sizeof(out6), "%s/%d %d", ifconfig_ipv6_local, tt->netbits_ipv6, tun_mtu);
    management_android_control(management, "IFCONFIG6", out6);
#elif defined(TARGET_SOLARIS)
    argv_printf(&argv, "%s %s inet6 unplumb", IFCONFIG_PATH, ifname);
    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, es, 0, NULL);

    if (tt->type == DEV_TYPE_TUN)
    {
        const char *ifconfig_ipv6_remote = print_in6_addr(tt->remote_ipv6, 0, &gc);

        argv_printf(&argv, "%s %s inet6 plumb %s/%d %s mtu %d up", IFCONFIG_PATH, ifname,
                    ifconfig_ipv6_local, tt->netbits_ipv6, ifconfig_ipv6_remote, tun_mtu);
    }
    else /* tap mode */
    {
        /* base IPv6 tap interface needs to be brought up first */
        argv_printf(&argv, "%s %s inet6 plumb up", IFCONFIG_PATH, ifname);
        argv_msg(M_INFO, &argv);

        if (!openvpn_execve_check(&argv, es, 0, "Solaris ifconfig IPv6 (prepare) failed"))
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
        argv_printf(&argv, "%s %s inet6 addif %s/%d up", IFCONFIG_PATH, ifname, ifconfig_ipv6_local,
                    tt->netbits_ipv6);
    }
    argv_msg(M_INFO, &argv);

    if (!openvpn_execve_check(&argv, es, 0, "Solaris ifconfig IPv6 failed"))
    {
        solaris_error_close(tt, es, ifname, true);
    }

    if (tt->type != DEV_TYPE_TUN)
    {
        argv_printf(&argv, "%s %s inet6 mtu %d", IFCONFIG_PATH, ifname, tun_mtu);
        argv_msg(M_INFO, &argv);
        openvpn_execve_check(&argv, es, 0, "Solaris ifconfig IPv6 mtu failed");
    }
#elif defined(TARGET_OPENBSD) || defined(TARGET_NETBSD) || defined(TARGET_DARWIN) \
    || defined(TARGET_FREEBSD) || defined(TARGET_DRAGONFLY)
    argv_printf(&argv, "%s %s inet6 %s/%d mtu %d up", IFCONFIG_PATH, ifname, ifconfig_ipv6_local,
                tt->netbits_ipv6, tun_mtu);
    argv_msg(M_INFO, &argv);

    openvpn_execve_check(&argv, es, S_FATAL, "generic BSD ifconfig inet6 failed");

#if defined(TARGET_FREEBSD) && __FreeBSD_version >= 1200000 && __FreeBSD_version < 1300000
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

    openvpn_execve_check(&argv, es, S_FATAL, "FreeBSD BSD 'ifconfig inet6 -ifdisabled' failed");
#endif

#elif defined(TARGET_AIX)
    argv_printf(&argv, "%s %s inet6 %s/%d mtu %d up", IFCONFIG_PATH, ifname, ifconfig_ipv6_local,
                tt->netbits_ipv6, tun_mtu);
    argv_msg(M_INFO, &argv);

    /* AIX ifconfig will complain if it can't find ODM path in env */
    es = env_set_create(NULL);
    env_set_add(es, "ODMDIR=/etc/objrepos");

    openvpn_execve_check(&argv, es, S_FATAL, "generic BSD ifconfig inet6 failed");

    env_set_destroy(es);
#else  /* platforms we have no IPv6 code for */
    msg(M_FATAL,
        "Sorry, but I don't know how to do IPv6 'ifconfig' commands on this operating system.  You should ifconfig your TUN/TAP device manually or use an --up script.");
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
 * @param tun_mtu   the MTU value to set the interface to
 * @param es        the environment to be used when executing the commands
 * @param ctx       the networking API opaque context
 */
static void
do_ifconfig_ipv4(struct tuntap *tt, const char *ifname, int tun_mtu, const struct env_set *es,
                 openvpn_net_ctx_t *ctx)
{
    /*
     * We only handle TUN/TAP devices here, not --dev null devices.
     */
    bool tun_p2p = is_tun_p2p(tt);

    if (tt->skip_bind == -1)
    {
        tt->local = htonl(inet_addr("127.1.1.1"));
    }

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

    if (tun_p2p)
    {
        if (net_addr_ptp_v4_add(ctx, ifname, &tt->local, &tt->remote_netmask) < 0)
        {
            msg(M_FATAL, "Linux can't add IP to interface %s", ifname);
        }
    }
    else
    {
        if (net_addr_v4_add(ctx, ifname, &tt->local, netmask_to_netbits2(tt->remote_netmask)) < 0)
        {
            msg(M_FATAL, "Linux can't add IP to interface %s", ifname);
        }
    }
#elif defined(TARGET_ANDROID)
    char out[64];

    snprintf(out, sizeof(out), "%s %s %d %s", ifconfig_local, ifconfig_remote_netmask, tun_mtu,
             print_topology(tt->topology));
    management_android_control(management, "IFCONFIG", out);

#elif defined(TARGET_SOLARIS)
    /* Solaris 2.6 (and 7?) cannot set all parameters in one go...
     * example:
     *    ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 up
     *    ifconfig tun2 netmask 255.255.255.255
     */
    if (tun_p2p)
    {
        argv_printf(&argv, "%s %s %s %s mtu %d up", IFCONFIG_PATH, ifname, ifconfig_local,
                    ifconfig_remote_netmask, tun_mtu);

        argv_msg(M_INFO, &argv);
        if (!openvpn_execve_check(&argv, es, 0, "Solaris ifconfig phase-1 failed"))
        {
            solaris_error_close(tt, es, ifname, false);
        }

        argv_printf(&argv, "%s %s netmask 255.255.255.255", IFCONFIG_PATH, ifname);
    }
    else if (tt->type == DEV_TYPE_TUN)
    {
        argv_printf(&argv, "%s %s %s %s netmask %s mtu %d up", IFCONFIG_PATH, ifname,
                    ifconfig_local, ifconfig_local, ifconfig_remote_netmask, tun_mtu);
    }
    else /* tap */
    {
        argv_printf(&argv, "%s %s %s netmask %s up", IFCONFIG_PATH, ifname, ifconfig_local,
                    ifconfig_remote_netmask);
    }

    argv_msg(M_INFO, &argv);
    if (!openvpn_execve_check(&argv, es, 0, "Solaris ifconfig phase-2 failed"))
    {
        solaris_error_close(tt, es, ifname, false);
    }

    if (!tun_p2p && tt->type == DEV_TYPE_TUN)
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

    in_addr_t remote_end; /* for "virtual" subnet topology */

    /*
     * On OpenBSD, tun interfaces are persistent if created with
     * "ifconfig tunX create", and auto-destroyed if created by
     * opening "/dev/tunX" (so we just use the /dev/tunX)
     */

    /* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
    if (tun_p2p)
    {
        argv_printf(&argv, "%s %s %s %s mtu %d netmask 255.255.255.255 up -link0", IFCONFIG_PATH,
                    ifname, ifconfig_local, ifconfig_remote_netmask, tun_mtu);
    }
    else if (tt->type == DEV_TYPE_TUN)
    {
        remote_end = create_arbitrary_remote(tt);
        argv_printf(&argv, "%s %s %s %s mtu %d netmask %s up -link0", IFCONFIG_PATH, ifname,
                    ifconfig_local, print_in_addr_t(remote_end, 0, &gc), tun_mtu,
                    ifconfig_remote_netmask);
    }
    else /* tap */
    {
        argv_printf(&argv, "%s %s %s netmask %s mtu %d link0", IFCONFIG_PATH, ifname,
                    ifconfig_local, ifconfig_remote_netmask, tun_mtu);
    }
    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, es, S_FATAL, "OpenBSD ifconfig failed");

    /* Add a network route for the local tun interface */
    if (!tun_p2p && tt->type == DEV_TYPE_TUN)
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
    in_addr_t remote_end = INADDR_ANY; /* for "virtual" subnet topology */

    if (tun_p2p)
    {
        argv_printf(&argv, "%s %s %s %s mtu %d netmask 255.255.255.255 up", IFCONFIG_PATH, ifname,
                    ifconfig_local, ifconfig_remote_netmask, tun_mtu);
    }
    else if (tt->type == DEV_TYPE_TUN)
    {
        remote_end = create_arbitrary_remote(tt);
        argv_printf(&argv, "%s %s %s %s mtu %d netmask %s up", IFCONFIG_PATH, ifname,
                    ifconfig_local, print_in_addr_t(remote_end, 0, &gc), tun_mtu,
                    ifconfig_remote_netmask);
    }
    else /* tap */
    {
        /*
         * NetBSD has distinct tun and tap devices
         * so we don't need the "link0" extra parameter to specify we want to do
         * tunneling at the ethernet level
         */
        argv_printf(&argv, "%s %s %s netmask %s mtu %d", IFCONFIG_PATH, ifname, ifconfig_local,
                    ifconfig_remote_netmask, tun_mtu);
    }
    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, es, S_FATAL, "NetBSD ifconfig failed");

    /* Add a network route for the local tun interface */
    if (!tun_p2p && tt->type == DEV_TYPE_TUN)
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
    msg(M_INFO, "NOTE: Tried to delete pre-existing tun/tap instance -- No Problem if failure");


    /* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
    if (tun_p2p)
    {
        argv_printf(&argv, "%s %s %s %s mtu %d netmask 255.255.255.255 up", IFCONFIG_PATH, ifname,
                    ifconfig_local, ifconfig_remote_netmask, tun_mtu);
    }
    else if (tt->type == DEV_TYPE_TUN)
    {
        argv_printf(&argv, "%s %s %s %s netmask %s mtu %d up", IFCONFIG_PATH, ifname,
                    ifconfig_local, ifconfig_local, ifconfig_remote_netmask, tun_mtu);
    }
    else /* tap */
    {
        argv_printf(&argv, "%s %s %s netmask %s mtu %d up", IFCONFIG_PATH, ifname, ifconfig_local,
                    ifconfig_remote_netmask, tun_mtu);
    }

    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, es, S_FATAL, "Mac OS X ifconfig failed");

    /* Add a network route for the local tun interface */
    if (!tun_p2p && tt->type == DEV_TYPE_TUN)
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
    if (tun_p2p) /* point-to-point tun */
    {
        argv_printf(&argv, "%s %s %s %s mtu %d netmask 255.255.255.255 up", IFCONFIG_PATH, ifname,
                    ifconfig_local, ifconfig_remote_netmask, tun_mtu);
    }
    else /* tun with topology subnet and tap mode (always subnet) */
    {
        int netbits = netmask_to_netbits2(tt->remote_netmask);
        argv_printf(&argv, "%s %s %s/%d mtu %d up", IFCONFIG_PATH, ifname, ifconfig_local, netbits,
                    tun_mtu);
    }

    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, es, S_FATAL, "FreeBSD ifconfig failed");

#elif defined(TARGET_AIX)
    {
        /* AIX ifconfig will complain if it can't find ODM path in env */
        struct env_set *aix_es = env_set_create(NULL);
        env_set_add(aix_es, "ODMDIR=/etc/objrepos");

        if (tt->type == DEV_TYPE_TUN)
        {
            msg(M_FATAL, "no tun support on AIX (canthappen)");
        }

        /* example: ifconfig tap0 172.30.1.1 netmask 255.255.254.0 up */
        argv_printf(&argv, "%s %s %s netmask %s mtu %d up", IFCONFIG_PATH, ifname, ifconfig_local,
                    ifconfig_remote_netmask, tun_mtu);

        argv_msg(M_INFO, &argv);
        openvpn_execve_check(&argv, aix_es, S_FATAL, "AIX ifconfig failed");

        env_set_destroy(aix_es);
    }

#elif defined(TARGET_HAIKU)
    /* example: ifconfig tun/0 inet 1.1.1.1 255.255.255.0 mtu 1450 up */
    argv_printf(&argv, "%s %s inet %s %s mtu %d up", IFCONFIG_PATH, ifname, ifconfig_local,
                ifconfig_remote_netmask, tun_mtu);

    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, es, S_FATAL, "Haiku ifconfig failed");
#else  /* if defined(TARGET_LINUX) */
    msg(M_FATAL,
        "Sorry, but I don't know how to do 'ifconfig' commands on this operating system.  You should ifconfig your TUN/TAP device manually or use an --up script.");
#endif /* if defined(TARGET_LINUX) */

#if !defined(TARGET_LINUX)
    gc_free(&gc);
    argv_free(&argv);
#endif
}

/* execute the ifconfig command through the shell */
void
do_ifconfig(struct tuntap *tt, const char *ifname, int tun_mtu, const struct env_set *es,
            openvpn_net_ctx_t *ctx)
{
    msg(D_LOW, "do_ifconfig, ipv4=%d, ipv6=%d", tt->did_ifconfig_setup,
        tt->did_ifconfig_ipv6_setup);

#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_set_state(management, OPENVPN_STATE_ASSIGN_IP, NULL, &tt->local, &tt->local_ipv6,
                             NULL, NULL);
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
        if (net_addr_ptp_v4_del(ctx, tt->actual_name, &tt->local, &tt->remote_netmask) < 0)
        {
            msg(M_WARN, "Linux can't del IP from iface %s", tt->actual_name);
        }
    }
    else
    {
        if (net_addr_v4_del(ctx, tt->actual_name, &tt->local, netbits) < 0)
        {
            msg(M_WARN, "Linux can't del IP from iface %s", tt->actual_name);
        }
    }
#elif defined(TARGET_FREEBSD)
    struct gc_arena gc = gc_new();
    const char *ifconfig_local = print_in_addr_t(tt->local, 0, &gc);
    struct argv argv = argv_new();

    argv_printf(&argv, "%s %s %s -alias", IFCONFIG_PATH, tt->actual_name, ifconfig_local);
    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, NULL, 0, "FreeBSD ip addr del failed");

    argv_free(&argv);
    gc_free(&gc);
#endif /* if defined(TARGET_LINUX) */
}

static void
undo_ifconfig_ipv6(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
#if defined(TARGET_LINUX)
    if (net_addr_v6_del(ctx, tt->actual_name, &tt->local_ipv6, tt->netbits_ipv6) < 0)
    {
        msg(M_WARN, "Linux can't del IPv6 from iface %s", tt->actual_name);
    }
#elif defined(TARGET_FREEBSD)
    struct gc_arena gc = gc_new();
    const char *ifconfig_ipv6_local = print_in6_addr(tt->local_ipv6, 0, &gc);
    struct argv argv = argv_new();

    argv_printf(&argv, "%s %s inet6 %s/%d -alias", IFCONFIG_PATH, tt->actual_name,
                ifconfig_ipv6_local, tt->netbits_ipv6);

    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, NULL, 0, "FreeBSD ip -6 addr del failed");

    argv_free(&argv);
    gc_free(&gc);
#endif /* if defined(TARGET_LINUX) */
}

void
undo_ifconfig(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    if (tt->backend_driver != DRIVER_NULL && tt->backend_driver != DRIVER_AFUNIX)
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
    tuntap->fd = -1;
#ifdef TARGET_SOLARIS
    tuntap->ip_fd = -1;
#endif
}

#if defined(TARGET_OPENBSD) || defined(TARGET_DARWIN)

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

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#endif

static int
write_tun_header(struct tuntap *tt, uint8_t *buf, int len)
{
    if (tt->type == DEV_TYPE_TUN)
    {
        u_int32_t type;
        struct iovec iv[2];
        struct openvpn_iphdr *iph;

        iph = (struct openvpn_iphdr *)buf;

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
        return write(tt->fe, buf, len);
    }
}

static int
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

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

#endif /* if defined (TARGET_OPENBSD) || defined(TARGET_DARWIN) */

bool
tun_name_is_fixed(const char *dev)
{
    return has_digit(dev);
}

#if defined(TARGET_LINUX) || defined(TARGET_FREEBSD)
static bool
tun_dco_enabled(struct tuntap *tt)
{
    return tt->backend_driver == DRIVER_DCO;
}
#endif


#if !(defined(TARGET_LINUX) || defined(TARGET_SOLARIS))
static void
open_tun_generic(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
    char tunname[256];
    char dynamic_name[256];
    bool dynamic_opened = false;

    /*
     * --dev-node specified, so open an explicit device node
     */
    if (dev_node)
    {
        snprintf(tunname, sizeof(tunname), "%s", dev_node);
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
                /* some platforms have a dedicated directory per driver */
                char *sep = "";
#if defined(TARGET_HAIKU)
                sep = "/";
#endif
                snprintf(tunname, sizeof(tunname), "/dev/%s%s%d", dev, sep, i);
                snprintf(dynamic_name, sizeof(dynamic_name), "%s%s%d", dev, sep, i);
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
            snprintf(tunname, sizeof(tunname), "/dev/%s", dev);
        }
    }

    if (!dynamic_opened)
    {
        /* has named device existed before? if so, don't destroy at end */
        if (if_nametoindex(dev) > 0)
        {
            msg(M_INFO, "TUN/TAP device %s exists previously, keep at program end", dev);
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
#endif /* !TARGET_LINUX && !TARGET_FREEBSD*/

#if defined(TARGET_LINUX) || defined(TARGET_FREEBSD)
static void
open_tun_dco_generic(const char *dev, const char *dev_type, struct tuntap *tt,
                     openvpn_net_ctx_t *ctx)
{
    char dynamic_name[256];
    bool dynamic_opened = false;

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
            snprintf(dynamic_name, sizeof(dynamic_name), "%s%d", dev, i);
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
            msg(M_INFO, "DCO device %s already exists, won't be destroyed at shutdown", dev);
            tt->persistent_if = true;
        }
        else if (ret < 0)
        {
            msg(M_ERR, "Cannot open DCO device %s: %s (%d)", dev, strerror(-ret), ret);
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

#if !(defined(TARGET_SOLARIS))
static void
close_tun_generic(struct tuntap *tt)
{
    if (tt->ff > 1)
    {
        close(tt->ff);
    }
    else if (tt->fd >= 0)
    {
        close(tt->fd);
    }
    free(tt->actual_name);
    clear_tuntap(tt);
}
#endif

#if defined(TARGET_ANDROID)
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

    int android_method = managment_android_persisttun_action(management);

    if (oldtunfd >= 0 && android_method == ANDROID_KEEP_OLD_TUN)
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
    return write(tt->fe, buf, len);
}

int
read_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    return read(tt->fd, buf, len);
}

#elif defined(TARGET_LINUX)

#if !PEDANTIC

void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
    struct ifreq ifr;

    if (tun_dco_enabled(tt))
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
            msg(M_FATAL, "I don't recognize device %s as a tun or tap device", dev);
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
        if (ioctl((tt->ff > 1) ? tt->ff : tt->fd, TUNSETIFF, (void *)&ifr) < 0)
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
                if (ioctl(ctl_fd, SIOCSIFTXQLEN, (void *)&netifr) >= 0)
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

void
tuncfg(const char *dev, const char *dev_type, const char *dev_node, int persist_mode,
       const char *username, const char *groupname, const struct tuntap_options *options,
       openvpn_net_ctx_t *ctx)
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

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#endif

int
write_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    return write(tt->fe, buf, len);
}

int
read_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    return read(tt->fd, buf, len);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

#elif defined(TARGET_SOLARIS)

#ifndef TUNNEWPPA
#error I need the symbol TUNNEWPPA from net/if_tun.h
#endif

void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
    int if_fd = -1, ip_muxid = -1, arp_muxid = -1, arp_fd = -1, ppa = -1;
    struct lifreq ifr;
    const char *ptr;
    const char *ip_node = NULL, *arp_node = NULL;
    const char *dev_tuntap_type;
    int link_type;
    struct strioctl strioc_if, strioc_ppa;

    /* improved generic TUN/TAP driver from
     * https://web.archive.org/web/20250504214754/http://www.whiteboard.ne.jp/~admin2/tuntap/
     * has IPv6 support
     */
    CLEAR(ifr);

    if (tt->type == DEV_TYPE_TUN)
    {
        ip_node = "/dev/udp";
        if (!dev_node)
        {
            dev_node = "/dev/tun";
        }
        dev_tuntap_type = "tun";
        link_type = I_PLINK;
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
    }
    else
    {
        msg(M_FATAL, "I don't recognize device %s as a tun or tap device", dev);
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
        while (*ptr && !isdigit((int)*ptr))
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

    if (*ptr == '\0') /* no number given, try dynamic */
    {
        bool found_one = false;
        while (!found_one && ppa < 64)
        {
            int new_ppa = ioctl(tt->fd, I_STR, &strioc_ppa);
            if (new_ppa >= 0)
            {
                msg(M_INFO, "open_tun: got dynamic interface '%s%d'", dev_tuntap_type, new_ppa);
                ppa = new_ppa;
                found_one = true;
                break;
            }
            if (errno != EEXIST)
            {
                msg(M_ERR, "open_tun: unexpected error trying to find free %s interface",
                    dev_tuntap_type);
            }
            ppa++;
        }
        if (!found_one)
        {
            msg(M_ERR, "open_tun: could not find free %s interface, give up.", dev_tuntap_type);
        }
    }
    else /* try this particular one */
    {
        if ((ppa = ioctl(tt->fd, I_STR, &strioc_ppa)) < 0)
        {
            msg(M_ERR, "Can't assign PPA for new interface (%s%d)", dev_tuntap_type, ppa);
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
        if (ioctl(if_fd, IF_UNITSEL, (char *)&ppa) < 0)
        {
            msg(M_ERR, "Can't set PPA %d", ppa);
        }
    }

    tt->actual_name = (char *)malloc(32);
    check_malloc_return(tt->actual_name);

    snprintf(tt->actual_name, 32, "%s%d", dev_tuntap_type, ppa);

    if (tt->type == DEV_TYPE_TAP)
    {
        if (ioctl(if_fd, SIOCGLIFFLAGS, &ifr) < 0)
        {
            msg(M_ERR, "Can't get flags");
        }
        strncpynt(ifr.lifr_name, tt->actual_name, sizeof(ifr.lifr_name));
        ifr.lifr_ppa = ppa;
        /* Assign ppa according to the unit number returned by tun device */
        if (ioctl(if_fd, SIOCSLIFNAME, &ifr) < 0)
        {
            msg(M_ERR, "Can't set PPA %d", ppa);
        }
        if (ioctl(if_fd, SIOCGLIFFLAGS, &ifr) < 0)
        {
            msg(M_ERR, "Can't get flags");
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
            msg(M_ERR, "Can't push ARP module");
        }

        /* Open arp_fd */
        if ((arp_fd = open(arp_node, O_RDWR, 0)) < 0)
        {
            msg(M_ERR, "Can't open %s", arp_node);
        }
        /* Push arp module to arp_fd */
        if (ioctl(arp_fd, I_PUSH, "arp") < 0)
        {
            msg(M_ERR, "Can't push ARP module");
        }

        /* Set ifname to arp */
        strioc_if.ic_cmd = SIOCSLIFNAME;
        strioc_if.ic_timout = 0;
        strioc_if.ic_len = sizeof(ifr);
        strioc_if.ic_dp = (char *)&ifr;
        if (ioctl(arp_fd, I_STR, &strioc_if) < 0)
        {
            msg(M_ERR, "Can't set ifname to arp");
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
    ifr.lifr_ip_muxid = ip_muxid;
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
        argv_printf(&argv, "%s %s inet6 unplumb", IFCONFIG_PATH, tt->actual_name);
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
solaris_error_close(struct tuntap *tt, const struct env_set *es, const char *actual,
                    bool unplumb_inet6)
{
    struct argv argv = argv_new();

    if (unplumb_inet6)
    {
        argv_printf(&argv, "%s %s inet6 unplumb", IFCONFIG_PATH, actual);
        argv_msg(M_INFO, &argv);
        openvpn_execve_check(&argv, es, 0, "Solaris ifconfig inet6 unplumb failed");
    }

    argv_printf(&argv, "%s %s unplumb", IFCONFIG_PATH, actual);

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

    argv_printf(&argv, "%s %s destroy", IFCONFIG_PATH, tt->actual_name);

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
        if ((tt->fd = open("/dev/tap", O_RDWR)) < 0)
        {
            msg(M_FATAL, "Cannot allocate NetBSD TAP dev dynamically");
        }
        if (ioctl(tt->fd, TAPGIFNAME, (void *)&ifr) < 0)
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
        int i = IFF_POINTOPOINT | IFF_MULTICAST;
        ioctl(tt->fd, TUNSIFMODE, &i); /* multicast on */
        i = 0;
        ioctl(tt->fd, TUNSLMODE, &i);  /* link layer mode off */

        if (tt->type == DEV_TYPE_TUN)
        {
            i = 1;
            if (ioctl(tt->fd, TUNSIFHEAD, &i) < 0) /* multi-af mode on */
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

    argv_printf(&argv, "%s %s destroy", IFCONFIG_PATH, tt->actual_name);

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

        iph = (struct openvpn_iphdr *)buf;

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
        return write(tt->fe, buf, len);
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

    if (tt->persistent_if) /* keep pre-existing if around */
    {
        close_tun_generic(tt);
        free(tt);
        return;
    }

    /* close and destroy */
    struct argv argv = argv_new();

    /* setup command, close tun dev (clears tt->actual_name!), run command
     */

    argv_printf(&argv, "%s %s destroy", IFCONFIG_PATH, tt->actual_name);

    close_tun_generic(tt);

    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, NULL, 0, "FreeBSD 'destroy tun interface' failed (non-critical)");

    free(tt);
    argv_free(&argv);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#endif

int
write_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    if (tt->type == DEV_TYPE_TUN)
    {
        u_int32_t type;
        struct iovec iv[2];
        struct ip *iph;

        iph = (struct ip *)buf;

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
        return write(tt->fe, buf, len);
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

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

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

        iph = (struct ip *)buf;

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
        return write(tt->fe, buf, len);
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
 * (https://www.cs.dartmouth.edu/~sergey/netreads/utun/utun-demo.c)
 */

/* Helper functions that tries to open utun device
 * return -2 on early initialization failures (utun not supported
 * at all) and -1 on initlization failure of utun
 * device (utun works but utunX is already used)
 */
static int
utun_open_helper(struct ctl_info ctlInfo, int utunnum)
{
    struct sockaddr_ctl sc;
    int fd;

    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

    if (fd < 0)
    {
        msg(M_INFO | M_ERRNO, "Opening utun%d failed (socket(SYSPROTO_CONTROL))", utunnum);
        return -2;
    }

    if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1)
    {
        close(fd);
        msg(M_INFO | M_ERRNO, "Opening utun%d failed (ioctl(CTLIOCGINFO))", utunnum);
        return -2;
    }


    sc.sc_id = ctlInfo.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;

    sc.sc_unit = utunnum + 1;


    /* If the connect is successful, a utun%d device will be created, where "%d"
     * is (sc.sc_unit - 1) */

    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0)
    {
        msg(M_INFO | M_ERRNO, "Opening utun%d failed (connect(AF_SYS_CONTROL))", utunnum);
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
    if (dev_node && (strcmp("utun", dev_node) != 0))
    {
        if (sscanf(dev_node, "utun%d", &utunnum) != 1)
        {
            msg(M_FATAL,
                "Cannot parse 'dev-node %s' please use 'dev-node utunX'"
                "to use a utun device number X",
                dev_node);
        }
    }


    CLEAR(ctlInfo);
    if (strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name))
        >= sizeof(ctlInfo.ctl_name))
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
            if (fd != -1)
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
    tt->backend_driver = DRIVER_UTUN;
}

void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
    /* If dev_node does not start start with utun assume regular tun/tap */
    if ((!dev_node && tt->type == DEV_TYPE_TUN) || (dev_node && !strncmp(dev_node, "utun", 4)))
    {
        /* Check if user has specific dev_type tap and forced utun with
         * dev-node utun */
        if (tt->type != DEV_TYPE_TUN)
        {
            msg(M_FATAL, "Cannot use utun devices with --dev-type %s",
                dev_type_string(dev, dev_type));
        }

        /* Try utun first and fall back to normal tun if utun fails
         * and dev_node is not specified */
        open_darwin_utun(dev, dev_type, dev_node, tt);

        if (tt->backend_driver != DRIVER_UTUN)
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
    {
        /* Use plain dev-node tun to select /dev/tun style
         * Unset dev_node variable prior to passing to open_tun_generic to
         * let open_tun_generic pick the first available tun device */

        if (dev_node && strcmp(dev_node, "tun") == 0)
        {
            dev_node = NULL;
        }

        open_tun_generic(dev, dev_type, dev_node, tt);
    }
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#endif

void
close_tun(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    ASSERT(tt);

    struct gc_arena gc = gc_new();
    struct argv argv = argv_new();

    if (tt->did_ifconfig_ipv6_setup)
    {
        const char *ifconfig_ipv6_local = print_in6_addr(tt->local_ipv6, 0, &gc);

        argv_printf(&argv, "%s delete -inet6 %s", ROUTE_PATH, ifconfig_ipv6_local);
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
    if (tt->backend_driver == DRIVER_UTUN)
    {
        return write_tun_header(tt, buf, len);
    }
    else
    {
        return write(tt->fe, buf, len);
    }
}

int
read_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    if (tt->backend_driver == DRIVER_UTUN)
    {
        return read_tun_header(tt, buf, len);
    }
    else
    {
        return read(tt->fd, buf, len);
    }
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

#elif defined(TARGET_AIX)

void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
    char tunname[256];
    char dynamic_name[20];
    const char *p;

    if (tt->type == DEV_TYPE_TUN)
    {
        msg(M_FATAL, "no support for 'tun' devices on AIX");
    }

    if (strncmp(dev, "tap", 3) != 0 || dev_node)
    {
        msg(M_FATAL,
            "'--dev %s' and/or '--dev-node' not supported on AIX, use '--dev tap0', 'tap1', etc.",
            dev);
    }

    if (strcmp(dev, "tap") == 0) /* find first free tap dev */
    {                            /* (= no /dev/tapN node) */
        int i;
        for (i = 0; i < 99; i++)
        {
            snprintf(tunname, sizeof(tunname), "/dev/tap%d", i);
            if (access(tunname, F_OK) < 0 && errno == ENOENT)
            {
                break;
            }
        }
        if (i >= 99)
        {
            msg(M_FATAL, "cannot find unused tap device");
        }

        snprintf(dynamic_name, sizeof(dynamic_name), "tap%d", i);
        dev = dynamic_name;
    }
    else /* name given, sanity check */
    {
        /* ensure that dev name is "tap+<digits>" *only* */
        p = &dev[3];
        while (isdigit(*p))
        {
            p++;
        }
        if (*p != '\0')
        {
            msg(M_FATAL, "TAP device name must be '--dev tapNNNN'");
        }

        snprintf(tunname, sizeof(tunname), "/dev/%s", dev);
    }

    /* pre-existing device?
     */
    if (access(tunname, F_OK) < 0 && errno == ENOENT)
    {
        /* tunnel device must be created with 'ifconfig tapN create'
         */
        struct argv argv = argv_new();
        struct env_set *es = env_set_create(NULL);
        argv_printf(&argv, "%s %s create", IFCONFIG_PATH, dev);
        argv_msg(M_INFO, &argv);
        env_set_add(es, "ODMDIR=/etc/objrepos");
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
        argv_printf(&argv, "%s %s 0.0.0.0 down", IFCONFIG_PATH, tt->actual_name);
    }
    else
    {
        argv_printf(&argv, "%s %s destroy", IFCONFIG_PATH, tt->actual_name);
    }

    close_tun_generic(tt);
    argv_msg(M_INFO, &argv);
    env_set_add(es, "ODMDIR=/etc/objrepos");
    openvpn_execve_check(&argv, es, 0, "AIX 'destroy tap interface' failed (non-critical)");

    free(tt);
    env_set_destroy(es);
    argv_free(&argv);
}

int
write_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    return write(tt->fe, buf, len);
}

int
read_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    return read(tt->fd, buf, len);
}

#else                        /* generic */

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
    return write(tt->fe, buf, len);
}

int
read_tun(struct tuntap *tt, uint8_t *buf, int len)
{
    return read(tt->fd, buf, len);
}

#endif                       /* if defined (TARGET_ANDROID) */
