#include "config.h"
#include "syshead.h"
#include "fuzzing.h"
#include "crypto.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
#if defined(ENABLE_CRYPTO) && defined(ENABLE_CRYPTO_OPENSSL)
    CRYPTO_malloc_init();
    SSL_library_init();
    ERR_load_crypto_strings();

    OpenSSL_add_all_algorithms();
    OpenSSL_add_ssl_algorithms();

    SSL_load_error_strings();
#else
#error "This fuzzing target cannot be built"
#endif
    return 1;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ssize_t choice;
    struct gc_arena gc;
    gc = gc_new();

    fuzzer_set_input((unsigned char*)data, size);
    FUZZER_GET_INTEGER(choice, 1);
    switch ( choice )
    {
        case    0:
            {
                struct key2 key2;
                char* input;
                FUZZER_GET_STRING_GC(input, 1024, &gc);
                read_key_file(&key2, (const char*)input, RKF_INLINE);
                break;
            }
        case    1:
            {
                struct key_type kt;
                char* ciphername, *authname;
                int keysize;
                int tls_mode;
                FUZZER_GET_STRING_GC(ciphername, 1024, &gc);
                FUZZER_GET_STRING_GC(authname, 1024, &gc);
                FUZZER_GET_INTEGER(keysize, (MAX_CIPHER_KEY_LENGTH+10));
                FUZZER_GET_INTEGER(tls_mode, 1);
                init_key_type(&kt, ciphername, authname, keysize, tls_mode ? true : false, 0);
            }
            break;
    }
cleanup:
    gc_free(&gc);
    return 0;
}
