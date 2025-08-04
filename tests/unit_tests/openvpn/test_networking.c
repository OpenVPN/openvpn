#include "config.h"
#include "syshead.h"
#include "networking.h"

#include <assert.h>

static char *iface = "ovpn-dummy0";

static int
net__iface_up(bool up)
{
    printf("CMD: ip link set %s %s\n", iface, up ? "up" : "down");

    return net_iface_up(NULL, iface, up);
}

static int
net__iface_new(const char *name, const char *type)
{
    return net_iface_new(NULL, name, type, NULL);
}

static int
net__iface_type(const char *name, const char *type)
{
    char ret_type[IFACE_TYPE_LEN_MAX];
    int ret = net_iface_type(NULL, name, ret_type);
    if (ret == 0)
    {
        assert(strcmp(type, ret_type) == 0);
    }

    return ret;
}

static int
net__iface_del(const char *name)
{
    return net_iface_del(NULL, name);
}

static int
net__iface_mtu_set(int mtu)
{
    printf("CMD: ip link set %s mtu %d\n", iface, mtu);

    return net_iface_mtu_set(NULL, iface, mtu);
}

static int
net__addr_v4_add(const char *addr_str, int prefixlen)
{
    in_addr_t addr;
    int ret;

    ret = inet_pton(AF_INET, addr_str, &addr);
    if (ret != 1)
    {
        return -1;
    }

    addr = ntohl(addr);

    printf("CMD: ip addr add %s/%d dev %s\n", addr_str, prefixlen, iface);

    return net_addr_v4_add(NULL, iface, &addr, prefixlen);
}

static int
net__addr_v6_add(const char *addr_str, int prefixlen)
{
    struct in6_addr addr;
    int ret;

    ret = inet_pton(AF_INET6, addr_str, &addr);
    if (ret != 1)
    {
        return -1;
    }

    printf("CMD: ip -6 addr add %s/%d dev %s\n", addr_str, prefixlen, iface);

    return net_addr_v6_add(NULL, iface, &addr, prefixlen);
}

static int
net__route_v4_add(const char *dst_str, int prefixlen, int metric)
{
    in_addr_t dst;
    int ret;

    if (!dst_str)
    {
        return -1;
    }

    ret = inet_pton(AF_INET, dst_str, &dst);
    if (ret != 1)
    {
        return -1;
    }

    dst = ntohl(dst);

    printf("CMD: ip route add %s/%d dev %s", dst_str, prefixlen, iface);
    if (metric > 0)
    {
        printf(" metric %d", metric);
    }
    printf("\n");

    return net_route_v4_add(NULL, &dst, prefixlen, NULL, iface, 0, metric);

}

static int
net__route_v4_add_gw(const char *dst_str, int prefixlen, const char *gw_str,
                     int metric)
{
    in_addr_t dst, gw;
    int ret;

    if (!dst_str || !gw_str)
    {
        return -1;
    }

    ret = inet_pton(AF_INET, dst_str, &dst);
    if (ret != 1)
    {
        return -1;
    }

    ret = inet_pton(AF_INET, gw_str, &gw);
    if (ret != 1)
    {
        return -1;
    }

    dst = ntohl(dst);
    gw = ntohl(gw);

    printf("CMD: ip route add %s/%d dev %s via %s", dst_str, prefixlen, iface,
           gw_str);
    if (metric > 0)
    {
        printf(" metric %d", metric);
    }
    printf("\n");

    return net_route_v4_add(NULL, &dst, prefixlen, &gw, iface, 0, metric);
}

static int
net__route_v6_add(const char *dst_str, int prefixlen, int metric)
{
    struct in6_addr dst;
    int ret;

    if (!dst_str)
    {
        return -1;
    }

    ret = inet_pton(AF_INET6, dst_str, &dst);
    if (ret != 1)
    {
        return -1;
    }

    printf("CMD: ip -6 route add %s/%d dev %s", dst_str, prefixlen, iface);
    if (metric > 0)
    {
        printf(" metric %d", metric);
    }
    printf("\n");

    return net_route_v6_add(NULL, &dst, prefixlen, NULL, iface, 0, metric);

}

static int
net__route_v6_add_gw(const char *dst_str, int prefixlen, const char *gw_str,
                     int metric)
{
    struct in6_addr dst, gw;
    int ret;

    if (!dst_str || !gw_str)
    {
        return -1;
    }

    ret = inet_pton(AF_INET6, dst_str, &dst);
    if (ret != 1)
    {
        return -1;
    }

    ret = inet_pton(AF_INET6, gw_str, &gw);
    if (ret != 1)
    {
        return -1;
    }

    printf("CMD: ip -6 route add %s/%d dev %s via %s", dst_str, prefixlen,
           iface, gw_str);
    if (metric > 0)
    {
        printf(" metric %d", metric);
    }
    printf("\n");

    return net_route_v6_add(NULL, &dst, prefixlen, &gw, iface, 0, metric);
}

static void
usage(char *name)
{
    printf("Usage: %s <0-8>\n", name);
}

int
main(int argc, char *argv[])
{
    int test;

    if (argc < 2)
    {
        usage(argv[0]);
        return -1;
    }

    /* the t_net script can use this command to perform a dry-run test */
    if (strcmp(argv[1], "test") == 0)
    {
        return 0;
    }

    if (argc > 3)
    {
        iface = argv[2];
    }

    test = atoi(argv[1]);
    switch (test)
    {
        case 0:
            return net__iface_up(true);

        case 1:
            return net__iface_mtu_set(1281);

        case 2:
            return net__addr_v4_add("10.255.255.1", 24);

        case 3:
            return net__addr_v6_add("2001::1", 64);

        case 4:
            return net__route_v4_add("11.11.11.0", 24, 0);

        case 5:
            return net__route_v4_add_gw("11.11.12.0", 24, "10.255.255.2", 0);

        case 6:
            return net__route_v6_add("2001:babe:cafe:babe::", 64, 600);

        case 7:
            return net__route_v6_add_gw("2001:cafe:babe::", 48, "2001::2", 600);

        /* following tests are standalone and do not print any CMD= */
        case 8:
            assert(net__iface_new("dummy0815", "dummy") == 0);
            assert(net__iface_type("dummy0815", "dummy") == 0);
            assert(net__iface_del("dummy0815") == 0);
            assert(net__iface_type("dummy0815", NULL) == -ENODEV);
            return 0;

        default:
            printf("invalid test: %d\n", test);
            break;
    }

    usage(argv[0]);
    return -1;
}
