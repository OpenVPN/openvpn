#include "config.h"
#include "syshead.h"
#include "fuzzing.h"
#include "dhcp.h"
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct gc_arena gc;
    struct buffer ipbuf;
    in_addr_t ret;

    ipbuf = alloc_buf(size);
    if ( buf_write(&ipbuf, data, size) == false ) {
        goto cleanup;
    }
    fuzzer_alter_buffer(&ipbuf);
    ret = dhcp_extract_router_msg(&ipbuf);
#ifdef MSAN
    test_undefined_memory(&ret, sizeof(ret));
#endif
cleanup:
    free_buf(&ipbuf);

    return 0;
}
