#include "config.h"
#include "syshead.h"
#include "fuzzing.h"
#include "base64.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char* str = NULL;
    unsigned char* outbuf;
    uint16_t* outsize;
    int ret;
    if ( size < sizeof(*outsize) )
    {
        return 0;
    }
    outsize = (uint16_t*)data;
    data += sizeof(*outsize);
    size -= sizeof(*outsize);
    if ( openvpn_base64_encode(data, size, &str) > 0 )
    {
#ifdef MSAN
        test_undefined_memory(str, strlen(str)+1);
#endif
    }
    free(str);
    str = malloc(size+1);
    memcpy(str, (char*)data, size);
    str[size] = 0;
    outbuf = malloc(*outsize);
    if ( (ret = openvpn_base64_decode(str, outbuf, *outsize)) > 0 )
    {
#ifdef MSAN
        test_undefined_memory(outbuf, ret);
#endif
    }
    free(str);
    free(outbuf);
    return 0;
}
#endif /* FUZZING */
