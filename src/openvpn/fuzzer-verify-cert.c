#include "config.h"
#include "syshead.h"

#if defined(ENABLE_CRYPTO_OPENSSL)
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#else
#endif

#include "fuzzing.h"
#include "fuzzer-verify-cert.h"
#include "misc.h"
#include "manage.h"
#include "otime.h"
#include "base64.h"
#include "ssl_verify.h"
#include "ssl_verify_backend.h"

#define SUBBUFFER_SIZE 256

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct tls_session* session;
    struct gc_arena gc;
    unsigned int generic_uint;
    ssize_t generic_ssizet;
    ssize_t nid;
#if defined(ENABLE_CRYPTO_OPENSSL)
    X509* x509 = NULL;
#else
    mbedtls_x509_crt x509;
#endif

    if ( size < SUBBUFFER_SIZE )
    {
        return 0;
    }

    gc = gc_new();

    fuzzer_set_input((unsigned char*)data, size);

    data += SUBBUFFER_SIZE;
    size -= SUBBUFFER_SIZE;

#if defined(ENABLE_CRYPTO_OPENSSL)
    x509 = d2i_X509(NULL, (const unsigned char**)&data, size);
    if ( x509 == NULL )
    {
        gc_free(&gc);
        return 0;
    }
#else
    mbedtls_x509_crt_init(&x509);
    if ( mbedtls_x509_crt_parse_der(&x509, data, size) != 0 ) {
        return 0;
    }
#endif
    ALLOC_OBJ_GC(session, struct tls_session, &gc);
    if ( session == NULL )
    {
        goto cleanup;
    }
    memset(session, 0xFE, sizeof(struct tls_session));
    
    ALLOC_OBJ_GC(session->opt, struct tls_options, &gc);
    if ( session->opt == NULL )
    {
        goto cleanup;
    }
    memset(session->opt, 0xFE, sizeof(struct tls_options));

    session->opt->es = env_set_create(&gc);
    session->common_name = NULL;
    session->opt->x509_username_field = NULL;
    session->opt->remote_cert_eku = NULL;
    FUZZER_GET_DATA(&generic_uint, sizeof(generic_uint));

    /* compat_flag() settings are accessed in string_mod_remap_name */
    compat_flag(generic_uint);

    /* Accessed in server_untrusted() */
    session->untrusted_addr.dest.addr.sa.sa_family = AF_UNSPEC;

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case    0:
            FUZZER_GET_INTEGER(nid, (sizeof(nidstrs)/sizeof(nidstrs[0])) - 1);
            session->opt->x509_username_field = nidstrs[nid];
            break;
        case    1:
            session->opt->x509_username_field = "ext:subjectAltName";
            break;
    }

    /* Accessed in set_common_name() */
    FUZZER_GET_STRING(session->common_name, 256);

    /* Prevents failure if x509 sha1 hashes do not match */
    session->opt->verify_hash = NULL;

    /* Prevent attempt to run --tls-verify script */
    session->opt->verify_command = NULL;

    /* Do not verify against CRL file */
    session->opt->crl_file = NULL;

    /* Do not run --tls-verify plugins */
    session->opt->plugins = NULL;

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case    0:
#if defined(ENABLE_CRYPTO_OPENSSL)
            session->opt->x509_track = NULL;
#else
            ALLOC_OBJ_GC(session->opt->x509_track, struct x509_track, &gc);
            if ( session->opt->x509_track == NULL )
            {
                goto cleanup;
            }
#endif
            break;
        case    1:
            session->opt->x509_track = NULL;
            break;
    }

    FUZZER_GET_INTEGER(generic_ssizet, 2);
    switch ( generic_ssizet )
    {
        case    0:
            session->opt->ns_cert_type = NS_CERT_CHECK_NONE;
            break;
        case    1:
            session->opt->ns_cert_type = NS_CERT_CHECK_SERVER;
            break;
        case    2:
            session->opt->ns_cert_type = NS_CERT_CHECK_CLIENT;
            break;
    }
    
    FUZZER_GET_DATA(&session->opt->remote_cert_ku, sizeof(session->opt->remote_cert_ku));

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
    case    0:
        session->opt->remote_cert_eku = NULL;
        break;
    case    1:
        FUZZER_GET_STRING(session->opt->remote_cert_eku, 256);
    }

    FUZZER_GET_INTEGER(generic_ssizet, 256);
#if defined(ENABLE_CRYPTO_OPENSSL)
    verify_cert(session, x509, generic_ssizet);
#else
    verify_cert(session, &x509, generic_ssizet);
#endif

cleanup:
    free(session->common_name);
    free((void*)session->opt->remote_cert_eku);
#if defined(ENABLE_CRYPTO_OPENSSL)
    X509_free(x509);
#else
    mbedtls_x509_crt_free(&x509);
#endif
    gc_free(&gc);
    return 0;
}
