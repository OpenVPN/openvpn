#include "config.h"
#include "syshead.h"
#include "fuzzing.h"
#include "base64.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}

void test_base64_encode(const uint8_t* data, size_t size)
{
    char* str = NULL;

    /* Base64-encode the entire input, store result in str */
    if ( openvpn_base64_encode(data, size, &str) > 0 )
    {
#ifdef MSAN
        test_undefined_memory(str, strlen(str)+1);
#endif
    }
    free(str);
}

void test_base64_decode(const uint8_t *data, size_t size)
{
    int ret;
    char* str = NULL;
    unsigned char* outbuf = NULL;
    uint16_t outsize;

    fuzzer_set_input((unsigned char*)data, size);

    /* Extract a number 0-65535 from the input stream, and allocate
     * a buffer that size. This will serve as the output buffer of the
     * base64 decoding function.
     *
     * This will test whether openvpn_base64_decode adheres to this
     * output buffer size. If not, OOB access will transpire via
     * AddressSanitizer */
    FUZZER_GET_INTEGER(outsize, 65535);
    outbuf = malloc(outsize);

    /* The remainder of the input buffer is used to create a
     * null-terminated string. This will serve as the input buffer
     * to openvpn_base64_decode(). */
    str = malloc(fuzzer_get_current_size()+1);
    memcpy(str, (char*)data, fuzzer_get_current_size());
    str[fuzzer_get_current_size()] = 0;

    if ( (ret = openvpn_base64_decode(str, outbuf, outsize)) > 0 )
    {
#ifdef MSAN
        test_undefined_memory(outbuf, ret);
#endif
    }

cleanup:
    free(str);
    free(outbuf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    test_base64_encode(data, size);
    test_base64_decode(data, size);

    return 0;
}
