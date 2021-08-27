/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
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

/**
 * @file Control Channel Verification Module
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "base64.h"
#include "manage.h"
#include "otime.h"
#include "run_command.h"
#include "ssl_verify.h"
#include "ssl_verify_backend.h"

#ifdef ENABLE_CRYPTO_OPENSSL
#include "ssl_verify_openssl.h"
#endif
#include "auth_token.h"
#include "push.h"
#include "ssl_util.h"

/** Maximum length of common name */
#define TLS_USERNAME_LEN 64

static void
string_mod_remap_name(char *str)
{
    string_mod(str, CC_PRINT, CC_CRLF, '_');
}

/*
 * Export the untrusted IP address and port to the environment
 */
static void
setenv_untrusted(struct tls_session *session)
{
    setenv_link_socket_actual(session->opt->es, "untrusted", &session->untrusted_addr, SA_IP_PORT);
}

/*
 * Remove authenticated state from all sessions in the given tunnel
 */
static void
tls_deauthenticate(struct tls_multi *multi)
{
    if (multi)
    {
        wipe_auth_token(multi);
        for (int i = 0; i < TM_SIZE; ++i)
        {
            for (int j = 0; j < KS_SIZE; ++j)
            {
                multi->session[i].key[j].authenticated = KS_AUTH_FALSE;
            }
        }
    }
}

/*
 * Set the given session's common_name
 */
static void
set_common_name(struct tls_session *session, const char *common_name)
{
    if (session->common_name)
    {
        free(session->common_name);
        session->common_name = NULL;
    }
    if (common_name)
    {
        /* FIXME: Last alloc will never be freed */
        session->common_name = string_alloc(common_name, NULL);
    }
}

/*
 * Retrieve the common name for the given tunnel's active session. If the
 * common name is NULL or empty, return NULL if null is true, or "UNDEF" if
 * null is false.
 */
const char *
tls_common_name(const struct tls_multi *multi, const bool null)
{
    const char *ret = NULL;
    if (multi)
    {
        ret = multi->session[TM_ACTIVE].common_name;
    }
    if (ret && strlen(ret))
    {
        return ret;
    }
    else if (null)
    {
        return NULL;
    }
    else
    {
        return "UNDEF";
    }
}

/*
 * Lock the common name for the given tunnel.
 */
void
tls_lock_common_name(struct tls_multi *multi)
{
    const char *cn = multi->session[TM_ACTIVE].common_name;
    if (cn && !multi->locked_cn)
    {
        multi->locked_cn = string_alloc(cn, NULL);
    }
}

/*
 * Lock the username for the given tunnel
 */
static bool
tls_lock_username(struct tls_multi *multi, const char *username)
{
    if (multi->locked_username)
    {
        if (!username || strcmp(username, multi->locked_username))
        {
            msg(D_TLS_ERRORS, "TLS Auth Error: username attempted to change from '%s' to '%s' -- tunnel disabled",
                multi->locked_username,
                np(username));

            /* disable the tunnel */
            tls_deauthenticate(multi);
            return false;
        }
    }
    else
    {
        if (username)
        {
            multi->locked_username = string_alloc(username, NULL);
        }
    }
    return true;
}

const char *
tls_username(const struct tls_multi *multi, const bool null)
{
    const char *ret = NULL;
    if (multi)
    {
        ret = multi->locked_username;
    }
    if (ret && strlen(ret))
    {
        return ret;
    }
    else if (null)
    {
        return NULL;
    }
    else
    {
        return "UNDEF";
    }
}

void
cert_hash_remember(struct tls_session *session, const int error_depth,
                   const struct buffer *cert_hash)
{
    if (error_depth >= 0 && error_depth < MAX_CERT_DEPTH)
    {
        if (!session->cert_hash_set)
        {
            ALLOC_OBJ_CLEAR(session->cert_hash_set, struct cert_hash_set);
        }
        if (!session->cert_hash_set->ch[error_depth])
        {
            ALLOC_OBJ(session->cert_hash_set->ch[error_depth], struct cert_hash);
        }

        struct cert_hash *ch = session->cert_hash_set->ch[error_depth];
        ASSERT(sizeof(ch->sha256_hash) == BLEN(cert_hash));
        memcpy(ch->sha256_hash, BPTR(cert_hash), sizeof(ch->sha256_hash));
    }
}

void
cert_hash_free(struct cert_hash_set *chs)
{
    if (chs)
    {
        int i;
        for (i = 0; i < MAX_CERT_DEPTH; ++i)
        {
            free(chs->ch[i]);
        }
        free(chs);
    }
}

bool
cert_hash_compare(const struct cert_hash_set *chs1, const struct cert_hash_set *chs2)
{
    if (chs1 && chs2)
    {
        int i;
        for (i = 0; i < MAX_CERT_DEPTH; ++i)
        {
            const struct cert_hash *ch1 = chs1->ch[i];
            const struct cert_hash *ch2 = chs2->ch[i];

            if (!ch1 && !ch2)
            {
                continue;
            }
            else if (ch1 && ch2 && !memcmp(ch1->sha256_hash, ch2->sha256_hash,
                                           sizeof(ch1->sha256_hash)))
            {
                continue;
            }
            else
            {
                return false;
            }
        }
        return true;
    }
    else if (!chs1 && !chs2)
    {
        return true;
    }
    else
    {
        return false;
    }
}

static struct cert_hash_set *
cert_hash_copy(const struct cert_hash_set *chs)
{
    struct cert_hash_set *dest = NULL;
    if (chs)
    {
        int i;
        ALLOC_OBJ_CLEAR(dest, struct cert_hash_set);
        for (i = 0; i < MAX_CERT_DEPTH; ++i)
        {
            const struct cert_hash *ch = chs->ch[i];
            if (ch)
            {
                ALLOC_OBJ(dest->ch[i], struct cert_hash);
                memcpy(dest->ch[i]->sha256_hash, ch->sha256_hash,
                       sizeof(dest->ch[i]->sha256_hash));
            }
        }
    }
    return dest;
}
void
tls_lock_cert_hash_set(struct tls_multi *multi)
{
    const struct cert_hash_set *chs = multi->session[TM_ACTIVE].cert_hash_set;
    if (chs && !multi->locked_cert_hash_set)
    {
        multi->locked_cert_hash_set = cert_hash_copy(chs);
    }
}

/*
 * Returns the string associated with the given certificate type.
 */
static const char *
print_nsCertType(int type)
{
    switch (type)
    {
        case NS_CERT_CHECK_SERVER:
            return "SERVER";

        case NS_CERT_CHECK_CLIENT:
            return "CLIENT";

        default:
            return "?";
    }
}

/*
 * Verify the peer's certificate fields.
 *
 * @param opt the tls options to verify against
 * @param peer_cert the peer's certificate
 * @param subject the peer's extracted subject name
 * @param subject the peer's extracted common name
 */
static result_t
verify_peer_cert(const struct tls_options *opt, openvpn_x509_cert_t *peer_cert,
                 const char *subject, const char *common_name)
{
    /* verify certificate nsCertType */
    if (opt->ns_cert_type != NS_CERT_CHECK_NONE)
    {
        if (SUCCESS == x509_verify_ns_cert_type(peer_cert, opt->ns_cert_type))
        {
            msg(D_HANDSHAKE, "VERIFY OK: nsCertType=%s",
                print_nsCertType(opt->ns_cert_type));
        }
        else
        {
            msg(D_HANDSHAKE, "VERIFY nsCertType ERROR: %s, require nsCertType=%s",
                subject, print_nsCertType(opt->ns_cert_type));
            return FAILURE;             /* Reject connection */
        }
    }

    /* verify certificate ku */
    if (opt->remote_cert_ku[0] != 0)
    {
        if (SUCCESS == x509_verify_cert_ku(peer_cert, opt->remote_cert_ku, MAX_PARMS))
        {
            msg(D_HANDSHAKE, "VERIFY KU OK");
        }
        else
        {
            msg(D_HANDSHAKE, "VERIFY KU ERROR");
            return FAILURE;             /* Reject connection */
        }
    }

    /* verify certificate eku */
    if (opt->remote_cert_eku != NULL)
    {
        if (SUCCESS == x509_verify_cert_eku(peer_cert, opt->remote_cert_eku))
        {
            msg(D_HANDSHAKE, "VERIFY EKU OK");
        }
        else
        {
            msg(D_HANDSHAKE, "VERIFY EKU ERROR");
            return FAILURE;             /* Reject connection */
        }
    }

    /* verify X509 name or username against --verify-x509-[user]name */
    if (opt->verify_x509_type != VERIFY_X509_NONE)
    {
        if ( (opt->verify_x509_type == VERIFY_X509_SUBJECT_DN
              && strcmp(opt->verify_x509_name, subject) == 0)
             || (opt->verify_x509_type == VERIFY_X509_SUBJECT_RDN
                 && strcmp(opt->verify_x509_name, common_name) == 0)
             || (opt->verify_x509_type == VERIFY_X509_SUBJECT_RDN_PREFIX
                 && strncmp(opt->verify_x509_name, common_name,
                            strlen(opt->verify_x509_name)) == 0) )
        {
            msg(D_HANDSHAKE, "VERIFY X509NAME OK: %s", subject);
        }
        else
        {
            msg(D_HANDSHAKE, "VERIFY X509NAME ERROR: %s, must be %s",
                subject, opt->verify_x509_name);
            return FAILURE;             /* Reject connection */
        }
    }

    return SUCCESS;
}

/*
 * Export the subject, common_name, and raw certificate fields to the
 * environment for later verification by scripts and plugins.
 */
static void
verify_cert_set_env(struct env_set *es, openvpn_x509_cert_t *peer_cert, int cert_depth,
                    const char *subject, const char *common_name,
                    const struct x509_track *x509_track)
{
    char envname[64];
    char *serial = NULL;
    struct gc_arena gc = gc_new();

    /* Save X509 fields in environment */
    if (x509_track)
    {
        x509_setenv_track(x509_track, es, cert_depth, peer_cert);
    }
    else
    {
        x509_setenv(es, cert_depth, peer_cert);
    }

    /* export subject name string as environmental variable */
    openvpn_snprintf(envname, sizeof(envname), "tls_id_%d", cert_depth);
    setenv_str(es, envname, subject);

#if 0
    /* export common name string as environmental variable */
    openvpn_snprintf(envname, sizeof(envname), "tls_common_name_%d", cert_depth);
    setenv_str(es, envname, common_name);
#endif

    /* export X509 cert fingerprints */
    {
        struct buffer sha1 = x509_get_sha1_fingerprint(peer_cert, &gc);
        struct buffer sha256 = x509_get_sha256_fingerprint(peer_cert, &gc);

        openvpn_snprintf(envname, sizeof(envname), "tls_digest_%d", cert_depth);
        setenv_str(es, envname,
                   format_hex_ex(BPTR(&sha1), BLEN(&sha1), 0, 1, ":", &gc));

        openvpn_snprintf(envname, sizeof(envname), "tls_digest_sha256_%d",
                         cert_depth);
        setenv_str(es, envname,
                   format_hex_ex(BPTR(&sha256), BLEN(&sha256), 0, 1, ":", &gc));
    }

    /* export serial number as environmental variable */
    serial = backend_x509_get_serial(peer_cert, &gc);
    openvpn_snprintf(envname, sizeof(envname), "tls_serial_%d", cert_depth);
    setenv_str(es, envname, serial);

    /* export serial number in hex as environmental variable */
    serial = backend_x509_get_serial_hex(peer_cert, &gc);
    openvpn_snprintf(envname, sizeof(envname), "tls_serial_hex_%d", cert_depth);
    setenv_str(es, envname, serial);

    gc_free(&gc);
}

/*
 * call --tls-verify plug-in(s)
 */
static result_t
verify_cert_call_plugin(const struct plugin_list *plugins, struct env_set *es,
                        int cert_depth, openvpn_x509_cert_t *cert, char *subject)
{
    if (plugin_defined(plugins, OPENVPN_PLUGIN_TLS_VERIFY))
    {
        int ret;
        struct argv argv = argv_new();

        argv_printf(&argv, "%d %s", cert_depth, subject);

        ret = plugin_call_ssl(plugins, OPENVPN_PLUGIN_TLS_VERIFY, &argv, NULL, es, cert_depth, cert);

        argv_free(&argv);

        if (ret == OPENVPN_PLUGIN_FUNC_SUCCESS)
        {
            msg(D_HANDSHAKE, "VERIFY PLUGIN OK: depth=%d, %s",
                cert_depth, subject);
        }
        else
        {
            msg(D_HANDSHAKE, "VERIFY PLUGIN ERROR: depth=%d, %s",
                cert_depth, subject);
            return FAILURE;             /* Reject connection */
        }
    }
    return SUCCESS;
}

static const char *
verify_cert_export_cert(openvpn_x509_cert_t *peercert, const char *tmp_dir, struct gc_arena *gc)
{
    FILE *peercert_file;
    const char *peercert_filename = "";

    /* create tmp file to store peer cert */
    if (!tmp_dir
        || !(peercert_filename = platform_create_temp_file(tmp_dir, "pcf", gc)))
    {
        msg(M_NONFATAL, "Failed to create peer cert file");
        return NULL;
    }

    /* write peer-cert in tmp-file */
    peercert_file = fopen(peercert_filename, "w+");
    if (!peercert_file)
    {
        msg(M_NONFATAL|M_ERRNO, "Failed to open temporary file: %s",
            peercert_filename);
        return NULL;
    }

    if (SUCCESS != x509_write_pem(peercert_file, peercert))
    {
        msg(M_NONFATAL, "Error writing PEM file containing certificate");
        (void) platform_unlink(peercert_filename);
        peercert_filename = NULL;
    }

    fclose(peercert_file);
    return peercert_filename;
}


/*
 * run --tls-verify script
 */
static result_t
verify_cert_call_command(const char *verify_command, struct env_set *es,
                         int cert_depth, openvpn_x509_cert_t *cert, char *subject, const char *verify_export_cert)
{
    const char *tmp_file = NULL;
    int ret;
    struct gc_arena gc = gc_new();
    struct argv argv = argv_new();

    setenv_str(es, "script_type", "tls-verify");

    if (verify_export_cert)
    {
        tmp_file = verify_cert_export_cert(cert, verify_export_cert, &gc);
        if (!tmp_file)
        {
            ret = false;
            goto cleanup;
        }
        setenv_str(es, "peer_cert", tmp_file);
    }

    argv_parse_cmd(&argv, verify_command);
    argv_printf_cat(&argv, "%d %s", cert_depth, subject);

    argv_msg_prefix(D_TLS_DEBUG, &argv, "TLS: executing verify command");
    ret = openvpn_run_script(&argv, es, 0, "--tls-verify script");

    if (verify_export_cert)
    {
        if (tmp_file)
        {
            platform_unlink(tmp_file);
        }
    }

cleanup:
    gc_free(&gc);
    argv_free(&argv);

    if (ret)
    {
        msg(D_HANDSHAKE, "VERIFY SCRIPT OK: depth=%d, %s",
            cert_depth, subject);
        return SUCCESS;
    }

    msg(D_HANDSHAKE, "VERIFY SCRIPT ERROR: depth=%d, %s",
        cert_depth, subject);
    return FAILURE;             /* Reject connection */
}

/*
 * check peer cert against CRL directory
 */
static result_t
verify_check_crl_dir(const char *crl_dir, openvpn_x509_cert_t *cert,
                     const char *subject, int cert_depth)
{
    result_t ret = FAILURE;
    char fn[256];
    int fd = -1;
    struct gc_arena gc = gc_new();

    char *serial = backend_x509_get_serial(cert, &gc);
    if (!serial)
    {
        msg(D_HANDSHAKE, "VERIFY CRL: depth=%d, %s, serial number is not available",
            cert_depth, subject);
        goto cleanup;
    }

    if (!openvpn_snprintf(fn, sizeof(fn), "%s%c%s", crl_dir, PATH_SEPARATOR, serial))
    {
        msg(D_HANDSHAKE, "VERIFY CRL: filename overflow");
        goto cleanup;
    }
    fd = platform_open(fn, O_RDONLY, 0);
    if (fd >= 0)
    {
        msg(D_HANDSHAKE, "VERIFY CRL: depth=%d, %s, serial=%s is revoked",
            cert_depth, subject, serial);
        goto cleanup;
    }

    ret = SUCCESS;

cleanup:

    if (fd != -1)
    {
        close(fd);
    }
    gc_free(&gc);
    return ret;
}

result_t
verify_cert(struct tls_session *session, openvpn_x509_cert_t *cert, int cert_depth)
{
    result_t ret = FAILURE;
    char *subject = NULL;
    const struct tls_options *opt;
    struct gc_arena gc = gc_new();

    opt = session->opt;
    ASSERT(opt);

    session->verified = false;

    /* get the X509 name */
    subject = x509_get_subject(cert, &gc);
    if (!subject)
    {
        msg(D_TLS_ERRORS, "VERIFY ERROR: depth=%d, could not extract X509 "
            "subject string from certificate", cert_depth);
        goto cleanup;
    }

    /* enforce character class restrictions in X509 name */
    string_mod_remap_name(subject);
    string_replace_leading(subject, '-', '_');

    /* extract the username (default is CN) */
    struct buffer buf = alloc_buf_gc(256, &gc);
    for (int i = 0; opt->x509_username_field[i] != NULL; i++)
    {
        char username[TLS_USERNAME_LEN+1] = {0}; /* null-terminated */

        if (SUCCESS != backend_x509_get_username(username, sizeof(username),
                                                 opt->x509_username_field[i], cert))
        {
            if (!cert_depth)
            {
                msg(D_TLS_ERRORS, "VERIFY ERROR: could not extract %s from X509 "
                    "subject string ('%s') -- note that the field length is "
                    "limited to %d characters",
                    opt->x509_username_field[i],
                    subject,
                    TLS_USERNAME_LEN);
                goto cleanup;
            }
            break;
        }
        if (!buf_printf(&buf, i ? "_%s" : "%s", username))
        {
            if (!cert_depth)
            {
                msg(D_TLS_ERRORS, "VERIFY ERROR: could not append %s from X509 "
                    "certificate -- note that the username length is "
                    "limited to %d characters",
                    opt->x509_username_field[i],
                    buf.capacity - 1);
                goto cleanup;
            }
            break;
        }
    }

    char *common_name = BSTR(&buf);
    if (!common_name)
    {
        msg(D_TLS_ERRORS, "VERIFY ERROR: depth=%d, could not extract X509 "
            "username string from certificate", cert_depth);
        goto cleanup;
    }

    /* enforce character class restrictions in common name */
    string_mod_remap_name(common_name);

    /* warn if cert chain is too deep */
    if (cert_depth >= MAX_CERT_DEPTH)
    {
        msg(D_TLS_ERRORS, "TLS Error: Convoluted certificate chain detected with depth [%d] greater than %d", cert_depth, MAX_CERT_DEPTH);
        goto cleanup;                   /* Reject connection */
    }

    if (cert_depth == opt->verify_hash_depth && opt->verify_hash)
    {
        struct buffer cert_fp = {0};

        switch (opt->verify_hash_algo)
        {
            case MD_SHA1:
                cert_fp = x509_get_sha1_fingerprint(cert, &gc);
                break;

            case MD_SHA256:
                cert_fp = x509_get_sha256_fingerprint(cert, &gc);
                break;

            default:
                /* This should normally not happen at all; the algorithm used
                 * is parsed by add_option() [options.c] and set to a predefined
                 * value in an enumerated type.  So if this unlikely scenario
                 * happens, consider this a failure
                 */
                msg(M_WARN, "Unexpected invalid algorithm used with "
                    "--verify-hash (%i)", opt->verify_hash_algo);
                ret = FAILURE;
                goto cleanup;
        }

        struct verify_hash_list *current_hash = opt->verify_hash;

        while (current_hash)
        {
            if (memcmp_constant_time(BPTR(&cert_fp), current_hash->hash,
                                     BLEN(&cert_fp)) == 0)
            {
                break;
            }
            current_hash = current_hash->next;
        }

        if (!current_hash)
        {
            const char *hex_fp = format_hex_ex(BPTR(&cert_fp), BLEN(&cert_fp),
                                               0, 1, ":", &gc);
            msg(D_TLS_ERRORS, "TLS Error: --tls-verify/--peer-fingerprint"
                "certificate hash verification failed. (got "
                "fingerprint: %s", hex_fp);
            goto cleanup;
        }
    }

    /* save common name in session object */
    if (cert_depth == 0)
    {
        set_common_name(session, common_name);
    }

    session->verify_maxlevel = max_int(session->verify_maxlevel, cert_depth);

    /* export certificate values to the environment */
    verify_cert_set_env(opt->es, cert, cert_depth, subject, common_name,
                        opt->x509_track);

    /* export current untrusted IP */
    setenv_untrusted(session);

    /* If this is the peer's own certificate, verify it */
    if (cert_depth == 0 && SUCCESS != verify_peer_cert(opt, cert, subject, common_name))
    {
        goto cleanup;
    }

    /* call --tls-verify plug-in(s), if registered */
    if (SUCCESS != verify_cert_call_plugin(opt->plugins, opt->es, cert_depth, cert, subject))
    {
        goto cleanup;
    }

    /* run --tls-verify script */
    if (opt->verify_command && SUCCESS != verify_cert_call_command(opt->verify_command,
                                                                   opt->es, cert_depth, cert, subject, opt->verify_export_cert))
    {
        goto cleanup;
    }

    /* check peer cert against CRL */
    if (opt->crl_file)
    {
        if (opt->ssl_flags & SSLF_CRL_VERIFY_DIR)
        {
            if (SUCCESS != verify_check_crl_dir(opt->crl_file, cert, subject, cert_depth))
            {
                goto cleanup;
            }
        }
        else
        {
            if (tls_verify_crl_missing(opt))
            {
                msg(D_TLS_ERRORS, "VERIFY ERROR: CRL not loaded");
                goto cleanup;
            }
        }
    }

    msg(D_HANDSHAKE, "VERIFY OK: depth=%d, %s", cert_depth, subject);
    session->verified = true;
    ret = SUCCESS;

cleanup:

    if (ret != SUCCESS)
    {
        tls_clear_error(); /* always? */
        session->verified = false; /* double sure? */
    }
    gc_free(&gc);

    return ret;
}

/* ***************************************************************************
* Functions for the management of deferred authentication when using
* user/password authentication.
*************************************************************************** */

void
auth_set_client_reason(struct tls_multi *multi, const char *client_reason)
{
    free(multi->client_reason);
    multi->client_reason = NULL;

    if (client_reason && strlen(client_reason))
    {
        multi->client_reason = string_alloc(client_reason, NULL);
    }
}

#ifdef ENABLE_MANAGEMENT

static inline enum auth_deferred_result
man_def_auth_test(const struct key_state *ks)
{
    if (management_enable_def_auth(management))
    {
        return ks->mda_status;
    }
    else
    {
        return ACF_DISABLED;
    }
}
#endif /* ifdef ENABLE_MANAGEMENT */

/**
 *  Removes auth_pending file from the file system
 *  and key_state structure
 */
static void
key_state_rm_auth_pending_file(struct auth_deferred_status *ads)
{
    if (ads && ads->auth_pending_file)
    {
        platform_unlink(ads->auth_pending_file);
        free(ads->auth_pending_file);
        ads->auth_pending_file = NULL;
    }
}

/**
 * Check peer_info if the client supports the requested pending auth method
 */
static bool
check_auth_pending_method(const char *peer_info, const char *method)
{
    struct gc_arena gc = gc_new();

    char *iv_sso = extract_var_peer_info(peer_info, "IV_SSO=", &gc);
    if (!iv_sso)
    {
        gc_free(&gc);
        return false;
    }

    const char *client_method = strtok(iv_sso, ",");
    bool supported = false;

    while (client_method)
    {
        if (0 == strcmp(client_method, method))
        {
            supported = true;
            break;
        }
        client_method = strtok(NULL, ",");
    }

    gc_free(&gc);
    return supported;
}

/**
 *  Checks if the deferred state should also send auth pending
 *  request to the client. Also removes the auth_pending control file
 *
 *  @returns true   if file was either processed sucessfully or did not
 *                  exist at all
 *  @returns false  The file had an invlaid format or another error occured
 */
static bool
key_state_check_auth_pending_file(struct auth_deferred_status *ads,
                                  struct tls_multi *multi)
{
    bool ret = true;
    if (ads->auth_pending_file)
    {
        struct buffer_list *lines = buffer_list_file(ads->auth_pending_file,
                                                     1024);
        if (lines && lines->head)
        {
            /* Must have at least three lines. further lines are ignored for
             * forward compatibility */
            if (!lines->head || !lines->head->next || !lines->head->next->next)
            {
                msg(M_WARN, "auth pending control file is not at least "
                            "three lines long.");
                buffer_list_free(lines);
                return false;
            }
            struct buffer *timeout_buf = &lines->head->buf;
            struct buffer *iv_buf = &lines->head->next->buf;
            struct buffer *extra_buf = &lines->head->next->next->buf;

            /* Remove newline chars at the end of the lines */
            buf_chomp(timeout_buf);
            buf_chomp(iv_buf);
            buf_chomp(extra_buf);

            long timeout = strtol(BSTR(timeout_buf), NULL, 10);
            if (timeout == 0)
            {
                msg(M_WARN, "could not parse auth pending file timeout");
                buffer_list_free(lines);
                return false;
            }

            const char* pending_method = BSTR(iv_buf);
            if (!check_auth_pending_method(multi->peer_info, pending_method))
            {
                char buf[128];
                openvpn_snprintf(buf, sizeof(buf),
                                 "Authentication failed, required pending auth "
                                 "method '%s' not supported", pending_method);
                auth_set_client_reason(multi, buf);
                msg(M_INFO, "Client does not supported auth pending method "
                            "'%s'", pending_method);
                ret = false;
            }
            else
            {
                send_auth_pending_messages(multi, BSTR(extra_buf), timeout);
            }
        }

        buffer_list_free(lines);
    }
    key_state_rm_auth_pending_file(ads);
    return ret;
}


/**
 *  Removes auth_pending and auth_control files from file system
 *  and key_state structure
 */
void
key_state_rm_auth_control_files(struct auth_deferred_status *ads)
{
    if (ads->auth_control_file)
    {
        platform_unlink(ads->auth_control_file);
        free(ads->auth_control_file);
        ads->auth_control_file = NULL;
    }
    key_state_rm_auth_pending_file(ads);
}

/**
 * Generates and creates the control files used for deferred authentification
 * in the temporary directory.
 *
 * @return  true if file creation was successful
 */
static bool
key_state_gen_auth_control_files(struct auth_deferred_status *ads,
                                 const struct tls_options *opt)
{
    struct gc_arena gc = gc_new();

    key_state_rm_auth_control_files(ads);
    const char *acf = platform_create_temp_file(opt->tmp_dir, "acf", &gc);
    const char *apf = platform_create_temp_file(opt->tmp_dir, "apf", &gc);

    if (acf && apf)
    {
        ads->auth_control_file = string_alloc(acf, NULL);
        ads->auth_pending_file = string_alloc(apf, NULL);
        setenv_str(opt->es, "auth_control_file", ads->auth_control_file);
        setenv_str(opt->es, "auth_pending_file", ads->auth_pending_file);
    }

    gc_free(&gc);
    return (acf && apf);
}

/**
 * Checks the auth control status from a file. The function will try 
 * to read and update the cached status if the status is still pending 
 * and the parameter cached is false. 
 * The function returns the most recent known status.
 *
 * @param ads       deferred status control structure
 * @param cached    Return only cached status
 * @return          ACF_* as per enum
 */
static enum auth_deferred_result
key_state_test_auth_control_file(struct auth_deferred_status *ads, bool cached)
{
    if (ads->auth_control_file)
    {
        unsigned int ret = ads->auth_control_status;
        if (ret == ACF_PENDING && !cached)
        {
            FILE *fp = fopen(ads->auth_control_file, "r");
            if (fp)
            {
                const int c = fgetc(fp);
                if (c == '1')
                {
                    ret = ACF_SUCCEEDED;
                }
                else if (c == '0')
                {
                    ret = ACF_FAILED;
                }
                fclose(fp);
                ads->auth_control_status = ret;
            }
        }
        return ret;
    }
    return ACF_DISABLED;
}

/**
 * This method takes a key_state and if updates the state
 * of the key if it is deferred.
 * @param cached    If auth control files should be tried to be opened or th
 *                  cached results should be used
 * @param ks        The key_state to update
 */
static void
update_key_auth_status(bool cached, struct key_state *ks)
{
    if (ks->authenticated == KS_AUTH_FALSE)
    {
        return;
    }
    else
    {
        enum auth_deferred_result auth_plugin = ACF_DISABLED;
        enum auth_deferred_result auth_script = ACF_DISABLED;
        enum auth_deferred_result auth_man = ACF_DISABLED;
        auth_plugin = key_state_test_auth_control_file(&ks->plugin_auth, cached);
        auth_script = key_state_test_auth_control_file(&ks->script_auth, cached);
#ifdef ENABLE_MANAGEMENT
        auth_man = man_def_auth_test(ks);
#endif
        ASSERT(auth_plugin < 4 && auth_script < 4 && auth_man < 4);

        if (auth_plugin == ACF_FAILED || auth_script == ACF_FAILED
           || auth_man == ACF_FAILED)
        {
            ks->authenticated = KS_AUTH_FALSE;
            return;
        }
        else if (auth_plugin == ACF_PENDING || auth_script == ACF_PENDING
                 || auth_man == ACF_PENDING)
        {
            if (now >= ks->auth_deferred_expire)
            {
                /* Window to authenticate the key has expired, mark
                 * the key as unauthenticated */
                ks->authenticated = KS_AUTH_FALSE;
            }
        }
        else
        {
            /* all auth states (auth_plugin, auth_script, auth_man)
             * are either ACF_DISABLED or ACF_SUCCEDED now, which
             * translates to "not checked" or "auth succeeded"
             */
            ks->authenticated = KS_AUTH_TRUE;
        }
    }
}


/**
 * The minimum times to have passed to update the cache. Older versions
 * of OpenVPN had code path that did not do any caching, so we start
 * with no caching (0) here as well to have the same super quick initial
 * reaction.
 */
static time_t cache_intervals[] = {0, 0, 0, 0, 0, 1, 1, 2, 2, 4, 8};

/**
 * uses cache_intervals times to determine if we should update the
 * cache.
 */
static bool
tls_authentication_status_use_cache(struct tls_multi *multi)
{
    unsigned int idx = min_uint(multi->tas_cache_num_updates, SIZE(cache_intervals) - 1);
    time_t latency = cache_intervals[idx];
    return multi->tas_cache_last_update + latency >= now;
}

enum tls_auth_status
tls_authentication_status(struct tls_multi *multi)
{
    bool deferred = false;

    /* at least one valid key has successfully completed authentication */
    bool success = false;

    /* at least one key is enabled for decryption */
    int active = 0;

    /* at least one key already failed authentication */
    bool failed_auth = false;

    bool cached = tls_authentication_status_use_cache(multi);

    for (int i = 0; i < KEY_SCAN_SIZE; ++i)
    {
        struct key_state *ks = get_key_scan(multi, i);
        if (TLS_AUTHENTICATED(multi, ks))
        {
            active++;
            update_key_auth_status(cached, ks);

            if (ks->authenticated == KS_AUTH_FALSE)
            {
                failed_auth = true;
            }
            else if (ks->authenticated == KS_AUTH_DEFERRED)
            {
                deferred = true;
            }
            else if (ks->authenticated == KS_AUTH_TRUE)
            {
                success = true;
            }
        }
    }

    /* we did not rely on a cached result, remember the cache update time */
    if (!cached)
    {
        multi->tas_cache_last_update = now;
        multi->tas_cache_num_updates++;
    }

#if 0
    dmsg(D_TLS_ERRORS, "TAS: a=%d s=%d d=%d f=%d", active, success, deferred, failed_auth);
#endif
    if (failed_auth)
    {
        /* We have at least one session that failed authentication. There
         * might be still another session with valid keys.
         * Although our protocol allows keeping the VPN session alive
         * with the other session (and we actually did that in earlier
         * version, this behaviour is really strange from a user (admin)
         * experience */
        return TLS_AUTHENTICATION_FAILED;
    }
    else if (success)
    {
        return TLS_AUTHENTICATION_SUCCEEDED;
    }
    else if (active == 0 || deferred)
    {
        /* We have a deferred authentication and no currently active key
         * (first auth, no renegotiation)  */
        return TLS_AUTHENTICATION_DEFERRED;
    }
    else
    {
        /* at least one key is active but none is fully authenticated (!success)
         * and all active are either failed authed or expired deferred auth */
        return TLS_AUTHENTICATION_FAILED;
    }
}

#ifdef ENABLE_MANAGEMENT
/*
 * For deferred auth, this is where the management interface calls (on server)
 * to indicate auth failure/success.
 */
bool
tls_authenticate_key(struct tls_multi *multi, const unsigned int mda_key_id, const bool auth, const char *client_reason)
{
    bool ret = false;
    if (multi)
    {
        int i;
        auth_set_client_reason(multi, client_reason);
        for (i = 0; i < KEY_SCAN_SIZE; ++i)
        {
            struct key_state *ks = get_key_scan(multi, i);
            if (ks->mda_key_id == mda_key_id)
            {
                ks->mda_status = auth ? ACF_SUCCEEDED : ACF_FAILED;
                ret = true;
            }
        }
    }
    return ret;
}
#endif /* ifdef ENABLE_MANAGEMENT */


/* ****************************************************************************
 * Functions to verify username and password
 *
 * Authenticate a client using username/password.
 * Runs on server.
 *
 * If you want to add new authentication methods,
 * this is the place to start.
 *************************************************************************** */

/*
 * Verify the user name and password using a script
 */
static int
verify_user_pass_script(struct tls_session *session, struct tls_multi *multi,
                        const struct user_pass *up)
{
    struct gc_arena gc = gc_new();
    struct argv argv = argv_new();
    const char *tmp_file = "";
    int retval = OPENVPN_PLUGIN_FUNC_ERROR;
    struct key_state *ks = &session->key[KS_PRIMARY];      /* primary key */

    /* Set environmental variables prior to calling script */
    setenv_str(session->opt->es, "script_type", "user-pass-verify");

    /* format command line */
    argv_parse_cmd(&argv, session->opt->auth_user_pass_verify_script);

    if (session->opt->auth_user_pass_verify_script_via_file)
    {
        struct status_output *so;

        tmp_file = platform_create_temp_file(session->opt->tmp_dir, "up",
                                             &gc);
        if (tmp_file)
        {
            so = status_open(tmp_file, 0, -1, NULL, STATUS_OUTPUT_WRITE);
            status_printf(so, "%s", up->username);
            status_printf(so, "%s", up->password);
            if (!status_close(so))
            {
                msg(D_TLS_ERRORS, "TLS Auth Error: could not write username/password to file: %s",
                    tmp_file);
                goto done;
            }
            /* pass temp file name to script */
            argv_printf_cat(&argv, "%s", tmp_file);
        }
    }
    else
    {
        setenv_str(session->opt->es, "username", up->username);
        setenv_str(session->opt->es, "password", up->password);
    }

    /* generate filename for deferred auth control file */
    if (!key_state_gen_auth_control_files(&ks->script_auth, session->opt))
    {
        msg(D_TLS_ERRORS, "TLS Auth Error (%s): "
                          "could not create deferred auth control file", __func__);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* call command */
    int script_ret = openvpn_run_script(&argv, session->opt->es, S_EXITCODE,
                                        "--auth-user-pass-verify");
    switch (script_ret)
    {
       case 0:
           retval = OPENVPN_PLUGIN_FUNC_SUCCESS;
           break;
       case 2:
           retval = OPENVPN_PLUGIN_FUNC_DEFERRED;
           break;
       default:
           retval = OPENVPN_PLUGIN_FUNC_ERROR;
           break;
    }
    if (retval == OPENVPN_PLUGIN_FUNC_DEFERRED)
    {
        /* Check if we the plugin has written the pending auth control
         * file and send the pending auth to the client */
        if(!key_state_check_auth_pending_file(&ks->script_auth,
                                              multi))
        {
            retval = OPENVPN_PLUGIN_FUNC_ERROR;
            key_state_rm_auth_control_files(&ks->script_auth);
        }

    }
    else
    {
        /* purge auth control filename (and file itself) for non-deferred returns */
        key_state_rm_auth_control_files(&ks->script_auth);
    }
    if (!session->opt->auth_user_pass_verify_script_via_file)
    {
        setenv_del(session->opt->es, "password");
    }

done:
    if (tmp_file && strlen(tmp_file) > 0)
    {
        platform_unlink(tmp_file);
    }

    argv_free(&argv);
    gc_free(&gc);
    return retval;
}

/*
 * Verify the username and password using a plugin
 */
static int
verify_user_pass_plugin(struct tls_session *session, struct tls_multi *multi,
                        const struct user_pass *up)
{
    int retval = OPENVPN_PLUGIN_FUNC_ERROR;
    struct key_state *ks = &session->key[KS_PRIMARY];      /* primary key */

    /* set password in private env space */
    setenv_str(session->opt->es, "password", up->password);

    /* generate filename for deferred auth control file */
    if (!key_state_gen_auth_control_files(&ks->plugin_auth, session->opt))
    {
        msg(D_TLS_ERRORS, "TLS Auth Error (%s): "
            "could not create deferred auth control file", __func__);
        return retval;
    }

    /* call command */
    retval = plugin_call(session->opt->plugins, OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY, NULL, NULL, session->opt->es);

    if (retval == OPENVPN_PLUGIN_FUNC_DEFERRED)
    {
        /* Check if the plugin has written the pending auth control
         * file and send the pending auth to the client */
        if(!key_state_check_auth_pending_file(&ks->plugin_auth, multi))
        {
            retval = OPENVPN_PLUGIN_FUNC_ERROR;
            key_state_rm_auth_control_files(&ks->plugin_auth);
        }
    }
    else
    {
        /* purge auth control filename (and file itself) for non-deferred returns */
        key_state_rm_auth_control_files(&ks->plugin_auth);
    }

    setenv_del(session->opt->es, "password");

    return retval;
}


#ifdef ENABLE_MANAGEMENT
/*
 * management deferred internal ssl_verify.c status codes
 */
#define KMDA_ERROR   0
#define KMDA_SUCCESS 1
#define KMDA_UNDEF   2
#define KMDA_DEF     3

static int
verify_user_pass_management(struct tls_session *session,
                            struct tls_multi *multi,
                            const struct user_pass *up)
{
    int retval = KMDA_ERROR;
    struct key_state *ks = &session->key[KS_PRIMARY];      /* primary key */

    /* set username/password in private env space */
    setenv_str(session->opt->es, "password", up->password);

    if (management)
    {
        management_notify_client_needing_auth(management, ks->mda_key_id, session->opt->mda_context, session->opt->es);
    }

    setenv_del(session->opt->es, "password");

    retval = KMDA_SUCCESS;

    return retval;
}
#endif /* ifdef ENABLE_MANAGEMENT */

static bool
set_verify_user_pass_env(struct user_pass *up, struct tls_multi *multi,
                         struct tls_session *session)
{
    /* Is username defined? */
    if ((session->opt->ssl_flags & SSLF_AUTH_USER_PASS_OPTIONAL) || strlen(up->username))
    {
        setenv_str(session->opt->es, "username", up->username);

        /* setenv incoming cert common name for script */
        setenv_str(session->opt->es, "common_name", session->common_name);

        /* setenv client real IP address */
        setenv_untrusted(session);

        /*
         * if we are using auth-gen-token, send also the session id of auth gen token to
         * allow the management to figure out if it is a new session or a continued one
         */
        add_session_token_env(session, multi, up);
        return true;
    }
    else
    {
        msg(D_TLS_ERRORS, "TLS Auth Error: peer provided a blank username");
        return false;
    }
}

/**
 * Main username/password verification entry point
 *
 * Will set session->ks[KS_PRIMARY].authenticated according to
 * result of the username/password verification
 */
void
verify_user_pass(struct user_pass *up, struct tls_multi *multi,
                 struct tls_session *session)
{
    struct key_state *ks = &session->key[KS_PRIMARY];      /* primary key */

#ifdef ENABLE_MANAGEMENT
    int man_def_auth = KMDA_UNDEF;

    if (management_enable_def_auth(management))
    {
        man_def_auth = KMDA_DEF;
    }
#endif

    /* enforce character class restrictions in username/password */
    string_mod_remap_name(up->username);
    string_mod(up->password, CC_PRINT, CC_CRLF, '_');

    /*
     * If auth token succeeds we skip the auth
     * methods unless otherwise specified
     */
    bool skip_auth = false;

    /*
     * If server is configured with --auth-gen-token and the client sends
     * something that looks like an authentication token, this
     * round will be done internally using the token instead of
     * calling any external authentication modules.
     */
    if (session->opt->auth_token_generate && is_auth_token(up->password))
    {
        ks->auth_token_state_flags = verify_auth_token(up, multi, session);

        /* If this is the first time we see an auth-token in this multi session,
         * save it as initial auth token. This ensures using the
         * same session ID and initial timestamp in new tokens */
        if (!multi->auth_token_initial)
        {
            multi->auth_token_initial = strdup(up->password);
        }

        if (session->opt->auth_token_call_auth)
        {
            /*
             * we do not care about the result here because it is
             * the responsibility of the external authentication to
             * decide what to do with the result
             */
        }
        else if (ks->auth_token_state_flags == AUTH_TOKEN_HMAC_OK)
        {
            /*
             * We do not want the EXPIRED or EMPTY USER flags here so check
             * for equality with AUTH_TOKEN_HMAC_OK
             */
            msg(M_WARN, "TLS: Username/auth-token authentication "
                "succeeded for username '%s'",
                up->username);
            skip_auth = true;
        }
        else
        {
            wipe_auth_token(multi);
            ks->authenticated = KS_AUTH_FALSE;
            msg(M_WARN, "TLS: Username/auth-token authentication "
                "failed for username '%s'", up->username);
            return;
        }
    }

    int plugin_status = OPENVPN_PLUGIN_FUNC_SUCCESS;
    int script_status = OPENVPN_PLUGIN_FUNC_SUCCESS;
    /* Set the environment variables used by all auth variants */
    if (!set_verify_user_pass_env(up, multi, session))
    {
        skip_auth = true;
        plugin_status = OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* call plugin(s) and/or script */
    if (!skip_auth)
    {
#ifdef ENABLE_MANAGEMENT
        if (man_def_auth == KMDA_DEF)
        {
            man_def_auth = verify_user_pass_management(session, multi, up);
        }
#endif
        if (plugin_defined(session->opt->plugins, OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY))
        {
            plugin_status = verify_user_pass_plugin(session, multi, up);
        }

        if (session->opt->auth_user_pass_verify_script)
        {
            script_status = verify_user_pass_script(session, multi, up);
        }
    }

    /* check sizing of username if it will become our common name */
    if ((session->opt->ssl_flags & SSLF_USERNAME_AS_COMMON_NAME)
        && strlen(up->username)>TLS_USERNAME_LEN)
    {
        msg(D_TLS_ERRORS,
            "TLS Auth Error: --username-as-common name specified and username is longer than the maximum permitted Common Name length of %d characters",
            TLS_USERNAME_LEN);
        plugin_status = OPENVPN_PLUGIN_FUNC_ERROR;
        script_status = OPENVPN_PLUGIN_FUNC_ERROR;
    }
    /* auth succeeded? */
    bool plugin_ok = plugin_status == OPENVPN_PLUGIN_FUNC_SUCCESS
        || plugin_status == OPENVPN_PLUGIN_FUNC_DEFERRED;

    bool script_ok =  script_status == OPENVPN_PLUGIN_FUNC_SUCCESS
        || script_status ==  OPENVPN_PLUGIN_FUNC_DEFERRED;

    if (script_ok && plugin_ok && tls_lock_username(multi, up->username)
#ifdef ENABLE_MANAGEMENT
        && man_def_auth != KMDA_ERROR
#endif
        )
    {
        ks->authenticated = KS_AUTH_TRUE;
        if (plugin_status == OPENVPN_PLUGIN_FUNC_DEFERRED
            || script_status == OPENVPN_PLUGIN_FUNC_DEFERRED)
        {
            ks->authenticated = KS_AUTH_DEFERRED;
        }
#ifdef ENABLE_MANAGEMENT
        if (man_def_auth != KMDA_UNDEF)
        {
            ks->authenticated = KS_AUTH_DEFERRED;
        }
#endif
        if ((session->opt->ssl_flags & SSLF_USERNAME_AS_COMMON_NAME))
        {
            set_common_name(session, up->username);
        }

        if ((session->opt->auth_token_generate))
        {
            /*
             * If we accepted a (not expired) token, i.e.
             * initial auth via token on new connection, we need
             * to store the auth-token in multi->auth_token, so
             * the initial timestamp and session id can be extracted from it
             */
            if (!multi->auth_token
                && (ks->auth_token_state_flags & AUTH_TOKEN_HMAC_OK)
                && !(ks->auth_token_state_flags & AUTH_TOKEN_EXPIRED))
            {
                multi->auth_token = strdup(up->password);
            }

            /*
             * Server is configured with --auth-gen-token. Generate or renew
             * the token.
             */
            generate_auth_token(up, multi);
        }

        msg(D_HANDSHAKE, "TLS: Username/Password authentication %s for username '%s' %s",
            (ks->authenticated == KS_AUTH_DEFERRED) ? "deferred" : "succeeded",
            up->username,
            (session->opt->ssl_flags & SSLF_USERNAME_AS_COMMON_NAME) ? "[CN SET]" : "");
    }
    else
    {
        ks->authenticated = KS_AUTH_FALSE;
        msg(D_TLS_ERRORS, "TLS Auth Error: Auth Username/Password verification failed for peer");
    }
}

void
verify_final_auth_checks(struct tls_multi *multi, struct tls_session *session)
{
    struct key_state *ks = &session->key[KS_PRIMARY];      /* primary key */

    /* While it shouldn't really happen, don't allow the common name to be NULL */
    if (!session->common_name)
    {
        set_common_name(session, "");
    }

    /* Don't allow the CN to change once it's been locked */
    if (ks->authenticated > KS_AUTH_FALSE && multi->locked_cn)
    {
        const char *cn = session->common_name;
        if (cn && strcmp(cn, multi->locked_cn))
        {
            msg(D_TLS_ERRORS, "TLS Auth Error: TLS object CN attempted to change from '%s' to '%s' -- tunnel disabled",
                multi->locked_cn,
                cn);

            /* change the common name back to its original value and disable the tunnel */
            set_common_name(session, multi->locked_cn);
            tls_deauthenticate(multi);
        }
    }

    /* Don't allow the cert hashes to change once they have been locked */
    if (ks->authenticated > KS_AUTH_FALSE && multi->locked_cert_hash_set)
    {
        const struct cert_hash_set *chs = session->cert_hash_set;
        if (chs && !cert_hash_compare(chs, multi->locked_cert_hash_set))
        {
            msg(D_TLS_ERRORS, "TLS Auth Error: TLS object CN=%s client-provided SSL certs unexpectedly changed during mid-session reauth",
                session->common_name);

            /* disable the tunnel */
            tls_deauthenticate(multi);
        }
    }

    /* verify --client-config-dir based authentication */
    if (ks->authenticated > KS_AUTH_FALSE && session->opt->client_config_dir_exclusive)
    {
        struct gc_arena gc = gc_new();

        const char *cn = session->common_name;
        const char *path = platform_gen_path(session->opt->client_config_dir_exclusive,
                                             cn, &gc);
        if (!cn || !strcmp(cn, CCD_DEFAULT) || !platform_test_file(path))
        {
            ks->authenticated = KS_AUTH_FALSE;
            wipe_auth_token(multi);
            msg(D_TLS_ERRORS, "TLS Auth Error: --client-config-dir authentication failed for common name '%s' file='%s'",
                session->common_name,
                path ? path : "UNDEF");
        }

        gc_free(&gc);
    }
}

void
tls_x509_clear_env(struct env_set *es)
{
    struct env_item *item = es->list;
    while (item)
    {
        struct env_item *next = item->next;
        if (item->string
            && 0 == strncmp("X509_", item->string, strlen("X509_")))
        {
            env_set_del(es, item->string);
        }
        item = next;
    }
}
