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

static int _init_options(struct options* options, struct client_nat_entry** cne, struct gc_arena *gc)
{
    ssize_t num_loops, generic_ssizet;
    size_t n;

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case 0:
            options->ce.mssfix = 0;
            break;
        case 1:
            options->ce.mssfix = 1;
            break;
    }

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case 0:
            options->passtos = false;
            break;
        case 1:
            options->passtos = true;
            break;
    }

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case 0:
            options->mode = MODE_POINT_TO_POINT;
            break;
        case 1:
            options->mode = MODE_SERVER;
            break;
    }

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case 0:
            options->allow_recursive_routing= true;
            break;
        case 1:
            options->allow_recursive_routing = false;
            break;
    }

    options->client_nat = new_client_nat_list(gc);

    FUZZER_GET_INTEGER(num_loops, MAX_CLIENT_NAT);
    for (n = 0; n < num_loops; n++) {
        struct client_nat_entry* _cne;
        ALLOC_ARRAY_GC(cne[n], struct client_nat_entry, 1, gc);
        _cne = cne[n];
        FUZZER_GET_DATA(_cne, sizeof(struct client_nat_entry));
        client_nat_add_entry(options->client_nat, _cne);
    }

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case 0:
            options->route_gateway_via_dhcp = false;
            break;
        case 1:
            options->route_gateway_via_dhcp = true;
            break;
    }

    return 0;

cleanup:
    return -1;
}

static int init_tuntap(struct tuntap* tuntap)
{
    ssize_t generic_ssizet;

    FUZZER_GET_INTEGER(generic_ssizet, 3);
    switch ( generic_ssizet )
    {
        case 0:
            tuntap->type = DEV_TYPE_UNDEF;
            break;
        case 1:
            tuntap->type = DEV_TYPE_NULL;
            break;
        case 2:
            tuntap->type = DEV_TYPE_TUN;
            break;
        case 3:
            tuntap->type = DEV_TYPE_TAP;
            break;
    }
    return 0;

cleanup:
    return -1;
}

static int init_c2(struct context_2* c2, struct gc_arena* gc)
{
    unsigned int generic_uint;
    ssize_t generic_ssizet;
    struct link_socket_actual* to_link_addr = NULL;
    struct link_socket* link_socket = NULL;
    struct buffer buf;

    memset(&buf, 0, sizeof(buf));

    ALLOC_ARRAY_GC(link_socket, struct link_socket, 1, gc);

    c2->link_socket = link_socket;

    c2->es = env_set_create(gc);

    FUZZER_GET_DATA(&generic_uint, sizeof(generic_uint));
    c2->frame.link_mtu_dynamic = generic_uint;
    FUZZER_GET_DATA(&generic_uint, sizeof(generic_uint));
    c2->frame.extra_frame = generic_uint;
    FUZZER_GET_DATA(&generic_uint, sizeof(generic_uint));
    c2->frame.extra_tun = generic_uint;

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case    0:
            c2->to_link_addr = NULL;
            break;
        case    1:
            ALLOC_ARRAY_GC(to_link_addr, struct link_socket_actual, 1, gc);
            FUZZER_GET_DATA(to_link_addr, sizeof(to_link_addr));
            c2->to_link_addr = to_link_addr;
            break;
    }

    if ( fuzzer_get_current_size() == 0 ) {
        goto cleanup;
    }

    buf = alloc_buf(fuzzer_get_current_size());

    if ( buf_write(&buf, fuzzer_get_current_data(), fuzzer_get_current_size()) == false ) {
        abort();
    }

    fuzzer_alter_buffer(&buf);
    c2->buf = buf;
    c2->log_rw = false;

    return 0;

cleanup:
    return -1;
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct gc_arena gc;
    struct client_nat_entry* cne[MAX_CLIENT_NAT];
    ssize_t generic_ssizet;
    unsigned int generic_uint;
    size_t n;
    counter_type counter;
    struct context ctx;
    struct tuntap tuntap;
    struct route_list route_list;

    memset(&ctx, 0, sizeof(ctx));
    memset(cne, 0, sizeof(cne));

    fuzzer_set_input((unsigned char*)data, size);
    gc = gc_new();

    if ( _init_options(&ctx.options, cne, &gc) == -1 ) {
        goto cleanup;
    }

    if ( init_tuntap(&tuntap) == -1 ) {
        goto cleanup;
    }

    ctx.c1.tuntap = &tuntap;

    if ( init_c2(&ctx.c2, &gc) == -1 ) {
        goto cleanup;
    }

    ctx.c1.route_list = &route_list;

    process_incoming_tun(&ctx);

cleanup:
    free_buf(&ctx.c2.buf);
    gc_free(&gc);

    return 0;
}
