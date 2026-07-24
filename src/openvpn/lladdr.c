/*
 * Support routine for configuring link layer address
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"
#include "error.h"
#include "misc.h"
#include "run_command.h"
#include "lladdr.h"
#include "proto.h"

#ifdef TARGET_LINUX
static int
set_lladdr_linux(openvpn_net_ctx_t *ctx, const char *ifname, const char *lladdr)
{
    uint8_t addr[OPENVPN_ETH_ALEN];

    sscanf(lladdr, MAC_FMT, MAC_SCAN_ARG(addr));
    return (net_addr_ll_set(ctx, ifname, addr) == 0);
}
#else /* TARGET_LINUX */

#if defined(TARGET_OPENBSD) || defined(TARGET_FREEBSD) || defined(TARGET_DARWIN)
#define IFCONFIG_LLADDR_FMT "%s %s lladdr %s"
#elif defined(TARGET_NETBSD)
#define IFCONFIG_LLADDR_FMT "%s %s link %s active"
#endif
static int
set_lladdr_ifconfig(const char *ifname, const char *lladdr, const struct env_set *es)
{
#ifdef IFCONFIG_LLADDR_FMT
    struct argv argv = argv_new();
    argv_printf(&argv, IFCONFIG_LLADDR_FMT, IFCONFIG_PATH, ifname, lladdr);
    argv_msg(M_INFO, &argv);
    int r = openvpn_execve_check(&argv, es, M_WARN, "ERROR: Unable to set link layer address.");
    argv_free(&argv);
    return r;
#else
    msg(M_WARN,
        "Sorry, but I don't know how to configure link layer addresses on this operating system.");
    return -1;
#endif
}
#endif /* TARGET_LINUX */

int
set_lladdr(openvpn_net_ctx_t *ctx, const char *ifname, const char *lladdr, const struct env_set *es)
{
    if (!ifname || !lladdr)
    {
        return -1;
    }

#if defined(TARGET_LINUX)
    int r = set_lladdr_linux(ctx, ifname, lladdr);
#else
    int r = set_lladdr_ifconfig(ifname, lladdr, es);
#endif

    if (r > 0)
    {
        msg(M_INFO, "TUN/TAP link layer address set to %s", lladdr);
    }

    return r;
}
