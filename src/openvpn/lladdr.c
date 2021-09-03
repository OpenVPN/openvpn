/*
 * Support routine for configuring link layer address
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"
#include "error.h"
#include "misc.h"
#include "run_command.h"
#include "lladdr.h"

int
set_lladdr(openvpn_net_ctx_t *ctx, const char *ifname, const char *lladdr,
           const struct env_set *es)
{
    int r;

    if (!ifname || !lladdr)
    {
        return -1;
    }

#if defined(TARGET_LINUX)
    uint8_t addr[ETH_ALEN];

    sscanf(lladdr, MAC_FMT, MAC_SCAN_ARG(addr));
    r = (net_addr_ll_set(ctx, ifname, addr) == 0);
#else /* if defined(TARGET_LINUX) */
    struct argv argv = argv_new();
#if defined(TARGET_SOLARIS)
    argv_printf(&argv,
                "%s %s ether %s",
                IFCONFIG_PATH,
                ifname, lladdr);
#elif defined(TARGET_OPENBSD)
    argv_printf(&argv,
                "%s %s lladdr %s",
                IFCONFIG_PATH,
                ifname, lladdr);
#elif defined(TARGET_DARWIN)
    argv_printf(&argv,
                "%s %s lladdr %s",
                IFCONFIG_PATH,
                ifname, lladdr);
#elif defined(TARGET_FREEBSD)
    argv_printf(&argv,
                "%s %s ether %s",
                IFCONFIG_PATH,
                ifname, lladdr);
#else  /* if defined(TARGET_SOLARIS) */
    msg(M_WARN, "Sorry, but I don't know how to configure link layer addresses on this operating system.");
    return -1;
#endif /* if defined(TARGET_SOLARIS) */
    argv_msg(M_INFO, &argv);
    r = openvpn_execve_check(&argv, es, M_WARN, "ERROR: Unable to set link layer address.");
    argv_free(&argv);
#endif /* if defined(TARGET_LINUX) */

    if (r)
    {
        msg(M_INFO, "TUN/TAP link layer address set to %s", lladdr);
    }

    return r;
}
