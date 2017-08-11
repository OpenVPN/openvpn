#include "config.h"
#include "syshead.h"
#include "fuzzing.h"
#include "buffer.h"
#include "openvpn.h"
#include "forward.h"
#include "clinat.h"
#include "proto.h"
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct gc_arena gc;
    struct buffer buf;
    struct client_nat_entry* cne[MAX_CLIENT_NAT];
    ssize_t num_loops, generic_ssizet;
    unsigned int generic_uint, flags;
    size_t n;
    counter_type counter;
    struct context ctx;
    struct tuntap tuntap;
    struct route_list route_list;
    struct link_socket link_socket;
    struct link_socket_actual to_link_addr;

    memset(cne, 0, sizeof(cne));

    fuzzer_set_input((unsigned char*)data, size);
    gc = gc_new();
    memset(&buf, 0, sizeof(buf));
    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case 0:
            ctx.options.ce.mssfix = 0;
            break;
        case 1:
            ctx.options.ce.mssfix = 1;
            break;
    }

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case 0:
            ctx.options.passtos = false;
            break;
        case 1:
            ctx.options.passtos = true;
            break;
    }

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case 0:
            ctx.options.mode = MODE_POINT_TO_POINT;
            break;
        case 1:
            ctx.options.mode = MODE_SERVER;
            break;
    }

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case 0:
            ctx.options.allow_recursive_routing= true;
            break;
        case 1:
            ctx.options.allow_recursive_routing = false;
            break;
    }

    ctx.options.client_nat = new_client_nat_list(&gc);

    FUZZER_GET_INTEGER(num_loops, MAX_CLIENT_NAT);
    for (n = 0; n < num_loops; n++) {
        struct client_nat_entry* _cne;
        cne[n] = malloc(sizeof(struct client_nat_entry));
        _cne = cne[n];
        FUZZER_GET_DATA(_cne, sizeof(struct client_nat_entry));
        client_nat_add_entry(ctx.options.client_nat, _cne);
    }

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case 0:
            ctx.options.route_gateway_via_dhcp = false;
            break;
        case 1:
            ctx.options.route_gateway_via_dhcp = true;
            break;
    }

    ctx.c1.tuntap = &tuntap;
    FUZZER_GET_INTEGER(generic_ssizet, 3);
    switch ( generic_ssizet )
    {
        case 0:
            tuntap.type = DEV_TYPE_UNDEF;
            break;
        case 1:
            tuntap.type = DEV_TYPE_NULL;
            break;
        case 2:
            tuntap.type = DEV_TYPE_TUN;
            break;
        case 3:
            tuntap.type = DEV_TYPE_TAP;
            break;
    }

    ctx.c1.route_list = &route_list;

    ctx.c2.link_socket = &link_socket;

    ctx.c2.es = env_set_create(&gc);

    FUZZER_GET_DATA(&generic_uint, sizeof(generic_uint));
    ctx.c2.frame.link_mtu_dynamic = generic_uint;
    FUZZER_GET_DATA(&generic_uint, sizeof(generic_uint));
    ctx.c2.frame.extra_frame = generic_uint;
    FUZZER_GET_DATA(&generic_uint, sizeof(generic_uint));
    ctx.c2.frame.extra_tun = generic_uint;

    FUZZER_GET_DATA(&flags, sizeof(flags));

    if ( fuzzer_get_current_size() == 0 ) {
        goto cleanup;
    }
    buf = alloc_buf(fuzzer_get_current_size());

    if ( buf_write(&buf, fuzzer_get_current_data(), fuzzer_get_current_size()) == false ) {
        abort();
    }

    fuzzer_alter_buffer(&buf);
    ctx.c2.buf = buf;
    ctx.c2.log_rw = false;

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case    0:
            ctx.c2.to_link_addr = NULL;
            break;
        case    1:
            FUZZER_GET_DATA(&to_link_addr, sizeof(to_link_addr));
            ctx.c2.to_link_addr = &to_link_addr;
            break;
    }

    process_incoming_tun(&ctx);
cleanup:
    for (n = 0; n < MAX_CLIENT_NAT; n++) {
        free(cne[n]);
    }
    free_buf(&buf);
    gc_free(&gc);

    return 0;
}
