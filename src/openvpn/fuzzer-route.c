#include "config.h"
#include "syshead.h"

#include "fuzzing.h"
#include "route.h"
#include "buffer.h"

static void serialize_route_bypass(struct route_bypass* bypass)
{
    test_undefined_memory(bypass->bypass, bypass->n_bypass * sizeof(bypass->bypass[0]));
}
static void serialize_route_special_addr(struct route_special_addr* spec)
{
    test_undefined_memory(&spec->flags, sizeof(spec->flags));
    test_undefined_memory(&spec->remote_endpoint, sizeof(spec->remote_endpoint));
    test_undefined_memory(&spec->remote_host, sizeof(spec->remote_host));
    test_undefined_memory(&spec->remote_host_local, sizeof(spec->remote_host_local));
    serialize_route_bypass(&spec->bypass);
    test_undefined_memory(&spec->default_metric, sizeof(spec->default_metric));
}

static void serialize_route_gateway_address(struct route_gateway_address* gateway)
{
    test_undefined_memory(&gateway->addr, sizeof(gateway->addr));
    test_undefined_memory(&gateway->netmask, sizeof(gateway->netmask));
}
static void serialize_route_gateway_info(struct route_gateway_info* rgi)
{
    int i;
    test_undefined_memory(&rgi->flags, sizeof(rgi->flags));
    test_undefined_memory(&rgi->iface, sizeof(rgi->iface));
    test_undefined_memory(&rgi->hwaddr, sizeof(rgi->hwaddr));
    serialize_route_gateway_address(&(rgi->gateway));
    for (i = 0; i < rgi->n_addrs; i++)
    {
        serialize_route_gateway_address(&(rgi->addrs[i]));
    }
}

static void serialize_route_ipv4(struct route_ipv4* route)
{
    test_undefined_memory(&route->flags, sizeof(route->flags));
    test_undefined_memory(&route->network, sizeof(route->network));
    test_undefined_memory(&route->netmask, sizeof(route->netmask));
    test_undefined_memory(&route->gateway, sizeof(route->gateway));
    if (route->flags & RT_METRIC_DEFINED)
    {
        test_undefined_memory(&route->metric, sizeof(route->metric));
    }
}

static void serialize_route_ipv4_list(struct route_ipv4* routes)
{
    while ( routes )
    {
        serialize_route_ipv4(routes);
        routes = routes->next;
    }
}
static void serialize_route_list(struct route_list* rl)
{
    test_undefined_memory(&rl->iflags, sizeof(rl->iflags));
    serialize_route_special_addr(&rl->spec);
    serialize_route_gateway_info(&rl->rgi);
    test_undefined_memory(&rl->flags, sizeof(rl->flags));
    if ( rl->routes )
    {
        serialize_route_ipv4_list(rl->routes);
    }
}

static void serialize_route_ipv6(struct route_ipv6* route)
{
    test_undefined_memory(&route->flags, sizeof(route->flags));
    test_undefined_memory(&route->network, sizeof(route->network));
    test_undefined_memory(&route->netbits, sizeof(route->netbits));
    test_undefined_memory(&route->gateway, sizeof(route->gateway));
    if (route->flags & RT_METRIC_DEFINED)
    {
        test_undefined_memory(&route->metric, sizeof(route->metric));
    }
}
static void serialize_route_ipv6_list(struct route_ipv6* routes)
{
    while ( routes )
    {
        serialize_route_ipv6(routes);
        routes = routes->next;
    }
}

static void serialize_route_ipv6_gateway_address(struct route_ipv6_gateway_address* gateway)
{
    test_undefined_memory(&gateway->addr_ipv6, sizeof(gateway->addr_ipv6));
    test_undefined_memory(&gateway->netbits_ipv6, sizeof(gateway->netbits_ipv6));
}

static void serialize_route_ipv6_gateway_info(struct route_ipv6_gateway_info* rgi)
{
    int i;

    test_undefined_memory(&rgi->flags, sizeof(rgi->flags));
    test_undefined_memory(&rgi->iface, sizeof(rgi->iface));
    test_undefined_memory(&rgi->hwaddr, sizeof(rgi->hwaddr));
    serialize_route_ipv6_gateway_address(&(rgi->gateway));
    for (i = 0; i < rgi->n_addrs; i++)
    {
        serialize_route_ipv6_gateway_address(&(rgi->addrs[i]));
    }
}
static void serialize_route6_list(struct route_ipv6_list* rl6)
{
    test_undefined_memory(&rl6->iflags, sizeof(rl6->iflags));
    test_undefined_memory(&rl6->spec_flags, sizeof(rl6->spec_flags));
    test_undefined_memory(&rl6->remote_endpoint_ipv6, sizeof(rl6->remote_endpoint_ipv6));
    test_undefined_memory(&rl6->remote_host_ipv6, sizeof(rl6->remote_host_ipv6));
    test_undefined_memory(&rl6->default_metric, sizeof(rl6->default_metric));
    serialize_route_ipv6_gateway_info(&rl6->rgi6);
    test_undefined_memory(&rl6->flags, sizeof(rl6->flags));
    if ( rl6->routes_ipv6 )
    {
        serialize_route_ipv6_list(rl6->routes_ipv6);
    }
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct buffer buf;
    struct env_set* es = NULL;
    struct route_list rl;
    struct route_ipv6_list rl6;
    struct route_option_list opt, *dest;
    struct route_ipv6_option_list opt6;
    struct gc_arena gc;
    ssize_t choice, input_size, num_loops, i;
    ssize_t netbits;
    unsigned char data2[10240];
    char* remote_endpoint = NULL;
    bool route_list_inited = false;
    bool route_ipv6_list_inited = false;

    fuzzer_set_input((unsigned char*)data, size);
    memset(&rl, 0, sizeof(rl));
    memset(&rl6, 0, sizeof(rl6));
    memset(&opt, 0, sizeof(opt));
    memset(&opt6, 0, sizeof(opt6));

    gc = gc_new();

    opt.gc = &gc;
    opt6.gc = &gc;
    add_route_to_option_list(&opt, "a", "b", "d", "c");

    es = env_set_create(&gc);

    FUZZER_GET_INTEGER(num_loops, 3);
    for (i = 0; i < num_loops; i++)
    {
        FUZZER_GET_INTEGER(choice, 0);
        switch ( choice )
        {
            case    0:
                if ( route_list_inited == false )
                {
                    in_addr_t remote_host;
                    ssize_t default_metric;
                    FUZZER_GET_DATA(&remote_host, sizeof(remote_host));
                    FUZZER_GET_DATA(&(opt.flags), sizeof(opt.flags));
                    FUZZER_GET_STRING_GC(remote_endpoint, 32, &gc);
                    FUZZER_GET_INTEGER(default_metric, 1);
                    if ( init_route_list(&rl, &opt, remote_endpoint, default_metric, remote_host, es) )
                    {
                        route_list_inited = true;
                    }
                }
                break;
            case    1:
                if ( route_list_inited == true )
                {
                    in_addr_t addr;
                    FUZZER_GET_DATA(&addr, sizeof(addr));
                    route_list_add_vpn_gateway(&rl, es, addr);
                }
            case    2:
                if ( route_list_inited == true )
                {
                    print_routes(&rl, 0);
                }
                break;
            case    3:
                dest = clone_route_option_list(&opt, &gc);
                break;
            case    4:
                {
                    unsigned int flags;
                    struct route_ipv4 r;
                    struct route_option ro;
                    FUZZER_GET_STRING_GC(ro.network, 32, &gc);
                    FUZZER_GET_STRING_GC(ro.netmask, 32, &gc);
                    FUZZER_GET_STRING_GC(ro.gateway, 32, &gc);
                    FUZZER_GET_STRING_GC(ro.netmask, 32, &gc);

                    FUZZER_GET_DATA(&flags, sizeof(flags));
                    
                    FUZZER_GET_DATA(&r.flags, sizeof(r.flags));
                    FUZZER_GET_DATA(&r.network, sizeof(r.network));
                    FUZZER_GET_DATA(&r.netmask, sizeof(r.netmask));
                    FUZZER_GET_DATA(&r.gateway, sizeof(r.gateway));
                    FUZZER_GET_DATA(&r.metric, sizeof(r.metric));
                    r.next = NULL;
                    r.option = &ro;

                    add_route(&r,
                            NULL,
                            flags,
                            NULL,
                            es);
                }
            case    5:
                {
                    unsigned int flags;
                    struct route_ipv6 r6;
                    struct tuntap tt;

                    memset(&tt, 0, sizeof(tt));

                    //FUZZER_GET_STRING_GC(tt.actual_name, 32, &gc);
                    tt.actual_name = string_alloc("X", &gc);

                    FUZZER_GET_DATA(&flags, sizeof(flags));
                    
                    FUZZER_GET_DATA(&r6.flags, sizeof(r6.flags));
                    FUZZER_GET_DATA(&r6.network, sizeof(r6.network));
                    FUZZER_GET_DATA(&r6.gateway, sizeof(r6.gateway));
                    FUZZER_GET_DATA(&r6.metric, sizeof(r6.metric));
                    FUZZER_GET_DATA(&r6.netbits, sizeof(r6.netbits));
                    FUZZER_GET_STRING_GC(r6.iface, 32, &gc);
                    /*r6.iface = string_alloc("Y", &gc);*/
                    r6.next = NULL;

                    add_route_ipv6(&r6,
                            &tt,
                            flags,
                            es);
                }
                break;
            case    6:
                if ( route_ipv6_list_inited == false )
                {
                    struct in6_addr remote_host;
                    char* remote_endpoint;
                    ssize_t default_metric;

                    FUZZER_GET_STRING_GC(remote_endpoint, 32, &gc);
                    FUZZER_GET_DATA(&remote_host, sizeof(remote_host));
                    FUZZER_GET_INTEGER(default_metric, 1);

                    if ( init_route_ipv6_list(&rl6, &opt6, remote_endpoint, default_metric, &remote_host, es) )
                    {
                        route_ipv6_list_inited = true;
                    }
                }
                break;
            case    7:
                if ( route_list_inited == true && route_ipv6_list_inited == true )
                {
                    unsigned int flags;
                    struct tuntap tt = {0};
                    FUZZER_GET_DATA(&flags, sizeof(flags));
                    FUZZER_GET_STRING_GC(tt.actual_name, 32, &gc);
                    //tt.actual_name = string_alloc("X", &gc);
                    add_routes(&rl, &rl6, &tt, flags, es);
                }
                break;
        }

    }
cleanup:
#ifdef MSAN
    if ( route_list_inited == true )
    {
        serialize_route_list(&rl);
    }
    if ( route_ipv6_list_inited == true )
    {
        serialize_route6_list(&rl6);
    }
#endif
    gc_free(&rl.gc);
    getaddrinfo_free_all();
    gc_free(&gc);
    return 0;
}
