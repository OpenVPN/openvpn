#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif
#include "syshead.h"
#include "errlevel.h"
#include "run_command.h"
#include "networking.h"

#if defined(TARGET_FREEBSD)

static int
net_route_v4(const char *op, const in_addr_t *dst, int prefixlen,
             const in_addr_t *gw, const char *iface, uint32_t table,
             int metric)
{
    char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];
    in_addr_t _dst, _gw;
    struct argv argv = argv_new();
    bool status;

    _dst = ntohl(*dst);
    _gw = ntohl(*gw);

    argv_printf(&argv, "%s %s -net %s/%d %s -fib %d",
                ROUTE_PATH, op,
                inet_ntop(AF_INET, &_dst, buf1, sizeof(buf1)),
                prefixlen,
                inet_ntop(AF_INET, &_gw, buf2, sizeof(buf2)),
                table);

    argv_msg(M_INFO, &argv);
    status = openvpn_execve_check(&argv, NULL, 0,
                                  "ERROR: FreeBSD route command failed");

    argv_free(&argv);

    return (!status);
}

static int
net_route_v6(const char *op, const struct in6_addr *dst,
             int prefixlen, const struct in6_addr *gw, const char *iface,
             uint32_t table, int metric)
{
    char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];
    struct argv argv = argv_new();
    bool status;

    argv_printf(&argv, "%s -6 %s -net %s/%d %s -fib %d",
                ROUTE_PATH, op,
                inet_ntop(AF_INET6, dst, buf1, sizeof(buf1)),
                prefixlen,
                inet_ntop(AF_INET6, gw, buf2, sizeof(buf2)),
                table);

    argv_msg(M_INFO, &argv);
    status = openvpn_execve_check(&argv, NULL, 0,
                                  "ERROR: FreeBSD route command failed");

    argv_free(&argv);

    return (!status);
}

int
net_route_v4_add(openvpn_net_ctx_t *ctx, const in_addr_t *dst, int prefixlen,
                 const in_addr_t *gw, const char *iface, uint32_t table,
                 int metric)
{
    return net_route_v4("add", dst, prefixlen, gw, iface, table, metric);
}

int
net_route_v6_add(openvpn_net_ctx_t *ctx, const struct in6_addr *dst,
                 int prefixlen, const struct in6_addr *gw, const char *iface,
                 uint32_t table, int metric)
{
    return net_route_v6("add", dst, prefixlen, gw, iface, table, metric);
}

int
net_route_v4_del(openvpn_net_ctx_t *ctx, const in_addr_t *dst, int prefixlen,
                 const in_addr_t *gw, const char *iface, uint32_t table,
                 int metric)
{
    return net_route_v4("del", dst, prefixlen, gw, iface, table, metric);
}

int
net_route_v6_del(openvpn_net_ctx_t *ctx, const struct in6_addr *dst,
                 int prefixlen, const struct in6_addr *gw, const char *iface,
                 uint32_t table, int metric)
{
    return net_route_v6("del", dst, prefixlen, gw, iface, table, metric);
}

#endif /* if defined(TARGET_FREEBSD) */
