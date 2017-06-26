#include "config.h"
#include "syshead.h"

#include "fuzzing.h"
#include "mroute.h"
#include "socket.h"
#include "buffer.h"

static void serialize_mroute_helper(struct mroute_helper* mh)
{
    test_undefined_memory(&mh->cache_generation, sizeof(mh->cache_generation));
    test_undefined_memory(&mh->ageable_ttl_secs, sizeof(mh->ageable_ttl_secs));
    test_undefined_memory(&mh->n_net_len, sizeof(mh->n_net_len));
    test_undefined_memory(&mh->net_len, mh->n_net_len * sizeof(mh->net_len[0]));
    test_undefined_memory(&mh->net_len_refcount, mh->n_net_len * sizeof(mh->net_len_refcount[0]));
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct mroute_addr src, dest, esrc, edest;
    struct mroute_helper* mh = NULL;
    struct openvpn_sockaddr osaddr;
    struct buffer buf;
    struct gc_arena gc, gc2;
    ssize_t choice, input_size, generic_ssizet, num_loops, i;
    ssize_t netbits;
    unsigned char data2[10240];

    fuzzer_set_input((unsigned char*)data, size);

    gc = gc_new();

    mroute_addr_init(&src);
    mroute_addr_init(&dest);
    mroute_addr_init(&esrc);
    mroute_addr_init(&edest);

    FUZZER_GET_INTEGER(num_loops, 16);
    for (i = 0; i < num_loops; i++)
    {
        FUZZER_GET_INTEGER(choice, 17);
        switch ( choice )
        {
            case    1:
                mroute_learnable_address(&src);
                break;
            case    2:
                {
                    int type;
                    FUZZER_GET_INTEGER(input_size, sizeof(data2));
                    FUZZER_GET_DATA(data2, input_size);
                    FUZZER_GET_INTEGER(generic_ssizet, 1);
                    type = generic_ssizet == 1 ? DEV_TYPE_TUN : DEV_TYPE_TAP;
                    buf = alloc_buf(size);
                    if ( buf_write(&buf, data2, input_size) == false ) {
                        goto cleanup;
                    }
                    fuzzer_alter_buffer(&buf);
                    mroute_extract_addr_from_packet(&src, &dest, &esrc, &edest, &buf, type);
                    free_buf(&buf);
                    break;
                }
            case    3:
                {
                    bool use_port;
                    FUZZER_GET_INTEGER(generic_ssizet, 1);
                    FUZZER_GET_DATA(&(osaddr.addr), sizeof(osaddr.addr));
                    use_port = generic_ssizet == 1 ? true : false;

                    mroute_extract_openvpn_sockaddr(&src, &osaddr, use_port);
                }
                break;
            case    4:
                mroute_addr_mask_host_bits(&src);
                break;
            case    5:
                {
                    struct buffer out;
                    gc2 = gc_new();
                    out = alloc_buf_gc(100, &gc2);
                    buf_printf(&out, "%s", mroute_addr_print(&src, &gc2));
                    mroute_addr_print(&src, &gc2);
                    if ( strlen(BSTR(&out)) == 1024 )
                    {
                        printf("X\n");
                    }
                    gc_free(&gc2);
                }
                break;
            case    6:
                {
                    unsigned int flags;
                    FUZZER_GET_DATA(&flags, sizeof(flags));
                    mroute_addr_print_ex(&src, flags, &gc);
                }
                break;
            case    7:
                mroute_addr_equal(&src, &dest);
                break;
            case    8:
                mroute_addr_equal(&src, &dest);
                break;
            case    9:
                {
                    in_addr_t x;
                    FUZZER_GET_DATA(&x, sizeof(x));
                    mroute_extract_in_addr_t(&src, x);
                }
                break;
            case    10:
                in_addr_t_from_mroute_addr(&src);
                break;
            case    11:
                mroute_addr_reset(&src);
                break;
            case    12:
                mroute_addr_hash_function(&src, 0xAABBCCDD);
                break;
            case    13:
                mroute_addr_compare_function(&src, &dest);
                break;
            case    14:
                if ( mh == NULL )
                {
                    int ageable_ttl_secs;
                    FUZZER_GET_DATA(&ageable_ttl_secs, sizeof(ageable_ttl_secs));
                    mh = mroute_helper_init(ageable_ttl_secs);
                }
                break;
            case    15:
                if ( mh )
                {
                    FUZZER_GET_INTEGER(netbits, 128);
                    mroute_helper_add_iroute46(mh, netbits);
                }
                break;
            case    16:
                if ( mh )
                {
                    FUZZER_GET_INTEGER(netbits, 128);
                    mroute_helper_del_iroute46(mh, netbits);
                }
                break;
            case    17:
                if ( mh )
                {
                    mroute_helper_free(mh);
                    mh = NULL;
                }
                break;
        }

        FUZZER_GET_INTEGER(choice, 4);
        switch ( choice )
        {
            case    0:
                dest = src;
                break;
            case    1:
                esrc = src;
                break;
            case    2:
                edest = src;
                break;
        }

        FUZZER_GET_DATA(&(src.mroute_union), sizeof(src.mroute_union));
        FUZZER_GET_INTEGER(netbits, 128);
        src.netbits = netbits;
    }
cleanup:
#ifdef MSAN
    if ( mh )
    {
        serialize_mroute_helper(mh);
    }
#endif
    mroute_helper_free(mh);
    gc_free(&gc);
    return 0;
}
