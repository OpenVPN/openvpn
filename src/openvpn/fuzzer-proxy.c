#include "config.h"
#include "syshead.h"
#include "fuzzing.h"
#include "proxy.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

int LLVMFuzzerInitialize(int *argc, char ***argv) {
#if defined(ENABLE_CRYPTO) && defined(ENABLE_CRYPTO_OPENSSL)
    CRYPTO_malloc_init();
    SSL_library_init();
    ERR_load_crypto_strings();

    OpenSSL_add_all_algorithms();
    OpenSSL_add_ssl_algorithms();

    SSL_load_error_strings();
    return 1;
#else
#error "This fuzzing target cannot be built"
#endif
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct gc_arena gc = gc_new();
    struct http_proxy_info pi;
    ssize_t len;
    ssize_t generic_ssizet;
    int signal_received = 0;
    struct buffer lookahead = alloc_buf(1024);

    fuzzer_set_input((unsigned char*)data, size);
    memset(&pi, 0, sizeof(pi));
    pi.proxy_authenticate = NULL;

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    fuzzer_set_recv_no_rnd((int)generic_ssizet);

    FUZZER_GET_INTEGER(len, USER_PASS_LEN-1);
    FUZZER_GET_DATA(pi.up.username, len);
    if ( strlen(pi.up.username) == 0 ) {
        goto cleanup;
    }

    FUZZER_GET_INTEGER(len, USER_PASS_LEN-1);
    FUZZER_GET_DATA(pi.up.password, len);
    pi.up.password[len] = 0;
    if ( strlen(pi.up.password) == 0 ) {
        goto cleanup;
    }

    FUZZER_GET_INTEGER(generic_ssizet, 4);
    switch ( generic_ssizet )
    {
        case    0:
            pi.auth_method = HTTP_AUTH_NONE;
            break;
        case    1:
            pi.auth_method = HTTP_AUTH_BASIC;
            break;
        case    2:
            pi.auth_method = HTTP_AUTH_DIGEST;
            break;
        case    3:
            pi.auth_method = HTTP_AUTH_NTLM;
            break;
        case    4:
            pi.auth_method = HTTP_AUTH_NTLM2;
            break;
    }
    pi.options.http_version = "1.1";

    FUZZER_GET_INTEGER(generic_ssizet, 2);
    switch ( generic_ssizet )
    {
        case    0:
            pi.options.auth_retry = PAR_NO;
            break;
        case    1:
            pi.options.auth_retry = PAR_ALL;
            break;
        case    2:
            pi.options.auth_retry = PAR_NCT;
            break;
    }

    FUZZER_GET_STRING(pi.proxy_authenticate, 256);
    
    establish_http_proxy_passthru(&pi, 0, "1.2.3.4", "777", NULL, &lookahead, &signal_received);
cleanup:
    free(pi.proxy_authenticate);
    gc_free(&gc);
    free_buf(&lookahead);
    return 0;
}
