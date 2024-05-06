/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2023-2024 Selva Nair <selva.nair@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by the
 *  Free Software Foundation, either version 2 of the License,
 *  or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"
#include "manage.h"
#include "base64.h"
#include "run_command.h"
#include "xkey_common.h"
#include "cert_data.h"
#include "pkcs11.h"
#include "ssl.h"

#include <setjmp.h>
#include <cmocka.h>
#include "test_common.h"

#define token_name "Test Token"
#define PIN "12345"
#define HASHSIZE 20


struct management *management; /* global */

/* replacement for crypto_print_openssl_errors() */
void
crypto_print_openssl_errors(const unsigned int flags)
{
    unsigned long e;
    while ((e = ERR_get_error()))
    {
        msg(flags, "OpenSSL error %lu: %s\n", e, ERR_error_string(e, NULL));
    }
}

/* stubs for some unused functions instead of pulling in too many dependencies */
int
parse_line(const char *line, char **p, const int n, const char *file,
           const int line_num, int msglevel, struct gc_arena *gc)
{
    assert_true(0);
    return 0;
}
char *
x509_get_subject(openvpn_x509_cert_t *cert, struct gc_arena *gc)
{
    return "N/A";
}
void
query_user_clear(void)
{
    assert_true(0);
}
bool
query_user_exec_builtin(void)
{
    assert_true(0);
    return false;
}
void
query_user_add(char *prompt, size_t prompt_len, char *resp, size_t resp_len, bool echo)
{
    (void) prompt;
    (void) prompt_len;
    (void) resp;
    (void) resp_len;
    (void) echo;
    assert_true(0);
}
void
purge_user_pass(struct user_pass *up, const bool force)
{
    (void) force;
    secure_memzero(up, sizeof(*up));
}

char *
management_query_pk_sig(struct management *man, const char *b64_data,
                        const char *algorithm)
{
    (void) man;
    (void) b64_data;
    (void) algorithm;
    return NULL;
}

int
digest_sign_verify(EVP_PKEY *privkey, EVP_PKEY *pubkey);

/* Test certificate database: data for cert1, cert2 .. key1, key2 etc.
 * are defined in cert_data.h
 */
static struct test_cert
{
    const char *const cert;             /* certificate as PEM */
    const char *const key;              /* key as unencrypted PEM */
    const char *const cname;            /* common-name */
    const char *const issuer;           /* issuer common-name */
    const char *const friendly_name;    /* identifies certs loaded to the store -- keep unique */
    uint8_t hash[HASHSIZE];             /* SHA1 fingerprint: computed and filled in later */
    char *p11_id;                       /* PKCS#11 id -- filled in later */
} certs[5];

static bool pkcs11_id_management;
static char softhsm2_tokens_path[] = "softhsm2_tokens_XXXXXX";
static char softhsm2_conf_path[] = "softhsm2_conf_XXXXXX";
int num_certs;
static const char *pkcs11_id_current;
struct env_set *es;

/* Fill-in certs[] array */
void
init_cert_data()
{
    struct test_cert certs_local[] = {
        {cert1,  key1,  cname1,  "OVPN TEST CA1",  "OVPN Test Cert 1",  {0},  NULL},
        {cert2,  key2,  cname2,  "OVPN TEST CA2",  "OVPN Test Cert 2",  {0},  NULL},
        {cert3,  key3,  cname3,  "OVPN TEST CA1",  "OVPN Test Cert 3",  {0},  NULL},
        {cert4,  key4,  cname4,  "OVPN TEST CA2",  "OVPN Test Cert 4",  {0},  NULL},
        {0}
    };
    assert(sizeof(certs_local) == sizeof(certs));
    memcpy(certs, certs_local, sizeof(certs_local));
}

/* Intercept get_user_pass for PIN and other prompts */
bool
get_user_pass_cr(struct user_pass *up, const char *auth_file, const char *prefix,
                 const unsigned int flags, const char *unused)
{
    (void) unused;
    bool ret = true;
    if (!strcmp(prefix, "pkcs11-id-request") && flags&GET_USER_PASS_NEED_STR)
    {
        assert_true(pkcs11_id_management);
        strncpynt(up->password, pkcs11_id_current, sizeof(up->password));
    }
    else if (flags & GET_USER_PASS_PASSWORD_ONLY)
    {
        snprintf(up->password, sizeof(up->password), "%s", PIN);
    }
    else
    {
        msg(M_NONFATAL, "ERROR: get_user_pass called with unknown request <%s> ignored\n", prefix);
        ret = false;
    }

    return ret;
}

/* Compute sha1 hash of a X509 certificate */
static void
sha1_fingerprint(X509 *x509, uint8_t *hash, int capacity)
{
    assert_true(capacity >= EVP_MD_size(EVP_sha1()));
    assert_int_equal(X509_digest(x509, EVP_sha1(), hash, NULL), 1);
}

#if defined(HAVE_XKEY_PROVIDER)
OSSL_LIB_CTX *tls_libctx;
OSSL_PROVIDER *prov[2];
#endif

static int
init(void **state)
{
    (void) state;

    umask(0077);  /* ensure all files and directories we create get user only access */
    char config[256];

    init_cert_data();
    if (!mkdtemp(softhsm2_tokens_path))
    {
        fail_msg("make tmpdir using template <%s> failed (error = %d)", softhsm2_tokens_path, errno);
    }

    int fd = mkstemp(softhsm2_conf_path);
    if (fd < 0)
    {
        fail_msg("make tmpfile using template <%s> failed (error = %d)", softhsm2_conf_path, errno);
    }
    snprintf(config, sizeof(config), "directories.tokendir=%s/",
             softhsm2_tokens_path);
    assert_int_equal(write(fd, config, strlen(config)), strlen(config));
    close(fd);

    /* environment */
    setenv("SOFTHSM2_CONF", softhsm2_conf_path, 1);
    es = env_set_create(NULL);
    setenv_str(es, "SOFTHSM2_CONF", softhsm2_conf_path);
    setenv_str(es, "GNUTLS_PIN", PIN);

    /* init the token using the temporary location as storage */
    struct argv a = argv_new();
    argv_printf(&a, "%s --init-token --free --label \"%s\" --so-pin %s --pin %s",
                SOFTHSM2_UTIL_PATH, token_name, PIN, PIN);
    assert_true(openvpn_execve_check(&a, es, 0, "Failed to initialize token"));

    /* Import certificates and keys in our test database into the token */
    char cert[] = "cert_XXXXXX";
    char key[] = "key_XXXXXX";
    int cert_fd = mkstemp(cert);
    int key_fd = mkstemp(key);
    if (cert_fd < 0 || key_fd < 0)
    {
        fail_msg("make tmpfile for certificate or key data failed (error = %d)", errno);
    }

    for (struct test_cert *c = certs; c->cert; c++)
    {
        /* fill-in the hash of the cert */
        BIO *buf = BIO_new_mem_buf(c->cert, -1);
        X509 *x509 = NULL;
        if (buf)
        {
            x509 = PEM_read_bio_X509(buf, NULL, NULL, NULL);
            BIO_free(buf);
        }
        assert_non_null(x509);
        sha1_fingerprint(x509, c->hash, HASHSIZE);
        X509_free(x509);

        /* we load all cert/key pairs even if expired as
         * signing should still work */
        assert_int_equal(write(cert_fd, c->cert, strlen(c->cert)), strlen(c->cert));
        assert_int_equal(write(key_fd, c->key, strlen(c->key)), strlen(c->key));

        argv_free(&a);
        a = argv_new();
        /* Use numcerts+1 as a unique id of the object  -- same id for matching cert and key */
        argv_printf(&a, "%s --provider %s --load-certificate %s --label \"%s\" --id %08x --login --write",
                    P11TOOL_PATH, SOFTHSM2_MODULE_PATH, cert, c->friendly_name, num_certs+1);
        assert_true(openvpn_execve_check(&a, es, 0, "Failed to upload certificate into token"));

        argv_free(&a);
        a = argv_new();
        argv_printf(&a, "%s --provider %s --load-privkey %s --label \"%s\" --id %08x --login --write",
                    P11TOOL_PATH, SOFTHSM2_MODULE_PATH, key, c->friendly_name, num_certs+1);
        assert_true(openvpn_execve_check(&a, es, 0, "Failed to upload key into token"));

        assert_int_equal(ftruncate(cert_fd, 0), 0);
        assert_int_equal(ftruncate(key_fd, 0), 0);
        num_certs++;
    }

    argv_free(&a);
    close(cert_fd);
    close(key_fd);
    unlink(cert);
    unlink(key);
    return 0;
}

static int
cleanup(void **state)
{
    (void) state;
    struct argv a = argv_new();

    argv_printf(&a, "%s --delete-token --token \"%s\"", SOFTHSM2_UTIL_PATH, token_name);
    assert_true(openvpn_execve_check(&a, es, 0, "Failed to delete token"));
    argv_free(&a);

    rmdir(softhsm2_tokens_path); /* this must be empty after delete token */
    unlink(softhsm2_conf_path);
    for (struct test_cert *c = certs; c->cert; c++)
    {
        free(c->p11_id);
        c->p11_id = NULL;
    }
    env_set_destroy(es);
    return 0;
}

static int
setup_pkcs11(void **state)
{
#if defined(HAVE_XKEY_PROVIDER)
    /* Initialize providers in a way matching what OpenVPN core does */
    tls_libctx = OSSL_LIB_CTX_new();
    prov[0] = OSSL_PROVIDER_load(tls_libctx, "default");
    OSSL_PROVIDER_add_builtin(tls_libctx, "ovpn.xkey", xkey_provider_init);
    prov[1] = OSSL_PROVIDER_load(tls_libctx, "ovpn.xkey");
    assert_non_null(prov[1]);

    /* set default propq as we do in ssl_openssl.c */
    EVP_set_default_properties(tls_libctx, "?provider!=ovpn.xkey");
#endif
    pkcs11_initialize(true, 0); /* protected auth enabled, pin-cache = 0 */
    pkcs11_addProvider(SOFTHSM2_MODULE_PATH, false, 0, false);
    return 0;
}

static int
teardown_pkcs11(void **state)
{
    pkcs11_terminate();
#if defined(HAVE_XKEY_PROVIDER)
    for (size_t i = 0; i < SIZE(prov); i++)
    {
        if (prov[i])
        {
            OSSL_PROVIDER_unload(prov[i]);
            prov[i] = NULL;
        }
    }
    OSSL_LIB_CTX_free(tls_libctx);
#endif
    return 0;
}

static struct test_cert *
lookup_cert_byhash(uint8_t *sha1)
{
    struct test_cert *c = certs;
    while (c->cert && memcmp(c->hash, sha1, HASHSIZE))
    {
        c++;
    }
    return c->cert ? c : NULL;
}

/* Enumerate usable items in the token and collect their pkcs11-ids */
static void
test_pkcs11_ids(void **state)
{
    char *p11_id = NULL;
    char *base64 = NULL;

    int n = pkcs11_management_id_count();
    assert_int_equal(n, num_certs);

    for (int i = 0; i < n; i++)
    {
        X509 *x509 = NULL;
        uint8_t sha1[HASHSIZE];

        /* We use the management interface functions as a quick way
         * to enumerate objects available for private key operations */
        if (!pkcs11_management_id_get(i, &p11_id, &base64))
        {
            fail_msg("Failed to get pkcs11-id for index (%d) from pkcs11-helper", i);
        }
        /* decode the base64 data and convert to X509 and get its sha1 fingerprint */
        unsigned char *der = malloc(strlen(base64));
        assert_non_null(der);
        int derlen = openvpn_base64_decode(base64, der, strlen(base64));
        free(base64);
        assert_true(derlen > 0);

        const unsigned char *ppin = der; /* alias needed as d2i_X509 alters the pointer */
        assert_non_null(d2i_X509(&x509, &ppin, derlen));
        sha1_fingerprint(x509, sha1, HASHSIZE);
        X509_free(x509);
        free(der);

        /* Save the pkcs11-id of this ceritificate in our database */
        struct test_cert *c = lookup_cert_byhash(sha1);
        assert_non_null(c);
        c->p11_id = p11_id; /* p11_id is freed in cleanup */
        assert_memory_equal(c->hash, sha1, HASHSIZE);
    }
    /* check whether all certs in our db were found by pkcs11-helper*/
    for (struct test_cert *c = certs; c->cert; c++)
    {
        if (!c->p11_id)
        {
            fail_msg("Certificate <%s> not enumerated by pkcs11-helper", c->friendly_name);
        }
    }
}

/* For each available pkcs11-id, load it into an SSL_CTX
 * and test signing with it.
 */
static void
test_tls_ctx_use_pkcs11(void **state)
{
    (void) state;
    struct tls_root_ctx tls_ctx = {};
    uint8_t sha1[HASHSIZE];
    for (struct test_cert *c = certs; c->cert; c++)
    {
#ifdef HAVE_XKEY_PROVIDER
        tls_ctx.ctx = SSL_CTX_new_ex(tls_libctx, NULL, SSLv23_client_method());
#else
        tls_ctx.ctx = SSL_CTX_new(SSLv23_client_method());
#endif
        if (pkcs11_id_management)
        {
            /* The management callback will return pkcs11_id_current as the
             * selection. Set it here as the current certificate's p11_id
             */
            pkcs11_id_current = c->p11_id;
            tls_ctx_use_pkcs11(&tls_ctx, 1, NULL);
        }
        else
        {
            /* directly use c->p11_id */
            tls_ctx_use_pkcs11(&tls_ctx, 0, c->p11_id);
        }

        /* check that the cert set in SSL_CTX is what we intended */
        X509 *x509 = SSL_CTX_get0_certificate(tls_ctx.ctx);
        assert_non_null(x509);
        sha1_fingerprint(x509, sha1, HASHSIZE);
        assert_memory_equal(sha1, c->hash, HASHSIZE);

        /* Test signing with the private key in SSL_CTX */
        EVP_PKEY *pubkey = X509_get0_pubkey(x509);
        EVP_PKEY *privkey = SSL_CTX_get0_privatekey(tls_ctx.ctx);
        assert_non_null(pubkey);
        assert_non_null(privkey);
#ifdef HAVE_XKEY_PROVIDER
        /* this will exercise signing via pkcs11 backend */
        assert_int_equal(digest_sign_verify(privkey, pubkey), 1);
#else
        if (!SSL_CTX_check_private_key(tls_ctx.ctx))
        {
            fail_msg("Certificate and private key in ssl_ctx do not match for <%s>", c->friendly_name);
            return;
        }
#endif
        SSL_CTX_free(tls_ctx.ctx);
    }
}

/* same test as test_tls_ctx_use_pkcs11, with id selected via management i/f */
static void
test_tls_ctx_use_pkcs11__management(void **state)
{
    pkcs11_id_management = true;
    test_tls_ctx_use_pkcs11(state);
}

int
main(void)
{
    openvpn_unit_test_setup();
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_pkcs11_ids, setup_pkcs11,
                                        teardown_pkcs11),
        cmocka_unit_test_setup_teardown(test_tls_ctx_use_pkcs11, setup_pkcs11,
                                        teardown_pkcs11),
        cmocka_unit_test_setup_teardown(test_tls_ctx_use_pkcs11__management, setup_pkcs11,
                                        teardown_pkcs11),
    };
    int ret = cmocka_run_group_tests_name("pkcs11_tests", tests, init, cleanup);

    return ret;
}
