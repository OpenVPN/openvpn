#include "config.h"
#include "syshead.h"

#if defined(ENABLE_CRYPTO_OPENSSL)
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
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

#define SUBBUFFER_SIZE 2048

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
#if defined(ENABLE_CRYPTO) && defined(ENABLE_CRYPTO_OPENSSL)
    CRYPTO_malloc_init();
    SSL_library_init();
    ERR_load_crypto_strings();

    OpenSSL_add_all_algorithms();
    OpenSSL_add_ssl_algorithms();

    SSL_load_error_strings();
    return 1;
#else
    /* Currently no PolarSSL/mbed TLS support */
#error "This fuzzing target cannot be built"
#endif
    return 1;
}

#if defined(ENABLE_CRYPTO_OPENSSL)
static int parse_x509(const uint8_t* data, size_t size, X509** out)
{
    *out = d2i_X509(NULL, (const unsigned char**)&data, size);
    if ( *out == NULL ) {
        return -1;
    }

    return 0;
}
#else
static int parse_x509(const uint8_t* data, size_t size, X509* out)
{
    mbedtls_x509_crt_init(x509);
    if ( mbedtls_x509_crt_parse_der(x509, data, size) != 0 ) {
        return -1;
    }

    return 0;
}
#endif

static int init_session_opt(struct tls_options** _opt, struct gc_arena* gc)
{
    ssize_t nid;
    ssize_t generic_ssizet;
    struct tls_options* opt;

    ALLOC_OBJ_GC(*_opt, struct tls_options, gc);
    if ( opt == NULL )
    {
        goto cleanup;
    }

    opt = *_opt;

    memset(opt, 0xFE, sizeof(struct tls_options));

    opt->es = env_set_create(gc);
    opt->x509_username_field = NULL;
    opt->remote_cert_eku = NULL;

    /* Prevents failure if x509 sha1 hashes do not match */
    opt->verify_hash = NULL;

    /* Prevent attempt to run --tls-verify script */
    opt->verify_command = NULL;

    /* Do not verify against CRL file */
    opt->crl_file = NULL;

    /* Do not run --tls-verify plugins */
    opt->plugins = NULL;

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case    0:
            FUZZER_GET_INTEGER(nid, (sizeof(nidstrs)/sizeof(nidstrs[0])) - 1);
            opt->x509_username_field = nidstrs[nid];
            break;
        case    1:
            opt->x509_username_field = "ext:subjectAltName";
            break;
    }

    FUZZER_GET_INTEGER(generic_ssizet, 2);
    switch ( generic_ssizet )
    {
        case    0:
            opt->ns_cert_type = NS_CERT_CHECK_NONE;
            break;
        case    1:
            opt->ns_cert_type = NS_CERT_CHECK_SERVER;
            break;
        case    2:
            opt->ns_cert_type = NS_CERT_CHECK_CLIENT;
            break;
    }

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case    0:
#if defined(ENABLE_CRYPTO_OPENSSL)
            opt->x509_track = NULL;
#else
            ALLOC_OBJ_GC(opt->x509_track, struct x509_track, gc);
            if ( opt->x509_track == NULL )
            {
                goto cleanup;
            }
#endif
            break;
        case    1:
            opt->x509_track = NULL;
            break;
    }

    FUZZER_GET_INTEGER(generic_ssizet, 1);
    switch ( generic_ssizet )
    {
        case    0:
            opt->remote_cert_eku = NULL;
            break;
        case    1:
            FUZZER_GET_STRING(opt->remote_cert_eku, 256);
    }

    FUZZER_GET_DATA(&(opt->remote_cert_ku), sizeof(opt->remote_cert_ku));

    return 0;

cleanup:
    return -1;
}

static int init_session(struct tls_session** _session, struct gc_arena* gc)
{
    struct tls_session* session;

    ALLOC_OBJ_GC(*_session, struct tls_session, gc);
    if ( session == NULL )
    {
        goto cleanup;
    }

    session = *_session;

    memset(session, 0xFE, sizeof(struct tls_session));

    /* Accessed in set_common_name() */
    FUZZER_GET_STRING(session->common_name, 256);

    /* Initialize the session->opt structure */
    if ( init_session_opt(&(session->opt), gc) == -1 ) {
        goto cleanup;
    }

    /* Accessed in server_untrusted() */
    session->untrusted_addr.dest.addr.sa.sa_family = AF_UNSPEC;


    return 0;

cleanup:
    return -1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct tls_session* session = NULL;
    struct gc_arena gc;
    unsigned int generic_uint;
    ssize_t generic_ssizet;
#if defined(ENABLE_CRYPTO_OPENSSL)
    X509* x509 = NULL;
#else
    mbedtls_x509_crt x509;
#endif

    /* The first SUBBUFFER_SIZE bytes of data is the region of the
     * fuzzer input from which data is culled to fill the
     * tls_session struct.
     *
     * The remainder of the data is treated as an X509 certificate
     */

    if ( size < SUBBUFFER_SIZE )
    {
        return 0;
    }

    gc = gc_new();

    fuzzer_set_input((unsigned char*)data, SUBBUFFER_SIZE);

    data += SUBBUFFER_SIZE;
    size -= SUBBUFFER_SIZE;

    if ( parse_x509(data, size, &x509) == -1 ) {
        gc_free(&gc);
        return 0;
    }

    if ( init_session(&session, &gc) == -1 ) {
        goto cleanup;
    }

    /* compat_flag() settings are accessed in string_mod_remap_name */
    FUZZER_GET_DATA(&generic_uint, sizeof(generic_uint));
    compat_flag(generic_uint);


    FUZZER_GET_INTEGER(generic_ssizet, 256);
#if defined(ENABLE_CRYPTO_OPENSSL)
    verify_cert(session, x509, generic_ssizet);
#else
    verify_cert(session, &x509, generic_ssizet);
#endif

cleanup:
    if ( session ) {
        /* common_name is the only session member that may contain
         * malloc'ed data */
        free(session->common_name);

        /* remote_cert_eku is the only session->opt member that
         * may contain malloc'ed data */
        if ( session->opt ) {
            free((void*)session->opt->remote_cert_eku);
        }
    }

#if defined(ENABLE_CRYPTO_OPENSSL)
    X509_free(x509);
#else
    mbedtls_x509_crt_free(&x509);
#endif

    gc_free(&gc);
    return 0;
}
