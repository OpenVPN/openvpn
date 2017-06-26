#include "config.h"
#include "syshead.h"
#include "fuzzing.h"
#include "buffer.h"
#include "lzo.h"
#include "comp.h"

#define SUBBUFFER_SIZE 256

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#ifdef ENABLE_LZO
    struct frame frame;
    struct buffer buf = {0}, buf2, workbuf = {0};
    struct buffer* bufptr;
    struct compress_context *compctx = NULL;
    ssize_t i, generic_ssizet, comp_alg, num_loops, data_size, operation;
    struct gc_arena gc;
    int initialized = 0;
    unsigned char data2[10240];
    size_t frame_buf_size;
    fuzzer_set_input((unsigned char*)data, size);
    gc = gc_new();
    FUZZER_GET_INTEGER(generic_ssizet, 1000);
    frame.link_mtu = generic_ssizet+100;
    FUZZER_GET_INTEGER(generic_ssizet, 1000);
    frame.extra_buffer = generic_ssizet+100;
    FUZZER_GET_INTEGER(generic_ssizet, 1000);
    frame.link_mtu_dynamic = generic_ssizet+100;
    FUZZER_GET_INTEGER(generic_ssizet, 1000);
    frame.extra_frame = generic_ssizet+100;
    FUZZER_GET_INTEGER(generic_ssizet, 1000);
    frame.extra_tun = generic_ssizet+100;
    FUZZER_GET_INTEGER(generic_ssizet, 1000);
    frame.extra_link = generic_ssizet+100;
    frame.align_flags = 0;
    frame.align_adjust = 0;
    frame_buf_size = BUF_SIZE(&frame);
    if ( PAYLOAD_SIZE(&frame) < 0 )
    {
        goto cleanup;
    }
    buf = alloc_buf(frame_buf_size);
    workbuf = alloc_buf(frame_buf_size);
    ALLOC_OBJ_CLEAR(compctx, struct compress_context);
    FUZZER_GET_INTEGER(comp_alg, 4);
    switch ( comp_alg )
    {
        case    0:
            FUZZER_GET_INTEGER(generic_ssizet, 1);
            if ( generic_ssizet == 0 )
            {
                compctx->flags = 0;
            }
            else
            {
                compctx->flags = COMP_F_ADAPTIVE;
            }
            compctx->alg = lzo_alg;
            break;
        case    1:
            compctx->flags = COMP_F_SWAP;
            compctx->alg = lz4_alg;
            break;
        case    2:
            compctx->flags = 0;
            compctx->alg = lz4v2_alg;
            break;
        case    3:
            FUZZER_GET_INTEGER(generic_ssizet, 1);
            if ( generic_ssizet == 0 )
            {
                compctx->flags = 0;
            }
            else
            {
                compctx->flags = COMP_F_SWAP;
            }
            compctx->alg = comp_stub_alg;
            break;
        case    4:
            FUZZER_GET_INTEGER(generic_ssizet, 1);
            if ( generic_ssizet == 0 )
            {
                compctx->flags = 0;
            }
            else
            {
                compctx->flags = COMP_F_SWAP;
            }
            compctx->alg = compv2_stub_alg;
            break;
    }
    (*compctx->alg.compress_init)(compctx);
    initialized = 1;

    FUZZER_GET_INTEGER(num_loops, 3);
    for (i = 0; i < num_loops; i++)
    {
        FUZZER_GET_INTEGER(operation, 1);
        FUZZER_GET_INTEGER(data_size, frame_buf_size);
        FUZZER_GET_DATA(data2, data_size);
        if ( buf_write(&buf, data2, data_size) == true ) {
            buf2 = buf;
            fuzzer_alter_buffer(&buf2);
            if ( operation == 0 )
            {
                (*compctx->alg.compress)(&buf2, workbuf, compctx, &frame);
            }
            else
            {
                (*compctx->alg.decompress)(&buf2, workbuf, compctx, &frame);
            }
#ifdef MSAN
            {
                test_undefined_memory(BPTR(&buf2), BLEN(&buf2));
            }
#endif
        }
    }
cleanup:
    if ( initialized )
    {
        (*compctx->alg.compress_uninit)(compctx);
    }
    free(compctx);
    gc_free(&gc);
    free_buf(&workbuf);
    free_buf(&buf);
    return 0;
#else
    static int inited = 0;
    if ( inited == 0 )
    {
        printf("\n\n\n\n\nOpenVPN has not been compiled with compression support. This fuzzer does nothing.\n\n\n\n\n");
        fflush(stdout);
        inited = 1;
    }
    return 0;
#endif
}
