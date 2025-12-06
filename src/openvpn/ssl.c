/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Sentyron B.V. <openvpn@sentyron.com>
 *  Copyright (C) 2008-2025 David Sommerseth <dazo@eurephia.org>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file
 * Control Channel SSL/Data channel negotiation Module
 */

/*
 * The routines in this file deal with dynamically negotiating
 * the data channel HMAC and cipher keys through a TLS session.
 *
 * Both the TLS session and the data channel are multiplexed
 * over the same TCP/UDP port.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"
#include "win32.h"

#include "error.h"
#include "common.h"
#include "socket.h"
#include "misc.h"
#include "fdmisc.h"
#include "interval.h"
#include "status.h"
#include "gremlin.h"
#include "pkcs11.h"
#include "route.h"
#include "tls_crypt.h"

#include "crypto_epoch.h"
#include "ssl.h"
#include "ssl_verify.h"
#include "ssl_backend.h"
#include "ssl_ncp.h"
#include "ssl_util.h"
#include "auth_token.h"
#include "mss.h"
#include "dco.h"

#include "memdbg.h"
#include "openvpn.h"

#ifdef MEASURE_TLS_HANDSHAKE_STATS

static int tls_handshake_success; /* GLOBAL */
static int tls_handshake_error;   /* GLOBAL */
static int tls_packets_generated; /* GLOBAL */
static int tls_packets_sent;      /* GLOBAL */

#define INCR_SENT      ++tls_packets_sent
#define INCR_GENERATED ++tls_packets_generated
#define INCR_SUCCESS   ++tls_handshake_success
#define INCR_ERROR     ++tls_handshake_error

void
show_tls_performance_stats(void)
{
    msg(D_TLS_DEBUG_LOW, "TLS Handshakes, success=%f%% (good=%d, bad=%d), retransmits=%f%%",
        (double)tls_handshake_success / (tls_handshake_success + tls_handshake_error) * 100.0,
        tls_handshake_success, tls_handshake_error,
        (double)(tls_packets_sent - tls_packets_generated) / tls_packets_generated * 100.0);
}
#else /* ifdef MEASURE_TLS_HANDSHAKE_STATS */

#define INCR_SENT
#define INCR_GENERATED
#define INCR_SUCCESS
#define INCR_ERROR

#endif /* ifdef MEASURE_TLS_HANDSHAKE_STATS */

/**
 * Limit the reneg_bytes value when using a small-block (<128 bytes) cipher.
 *
 * @param ciphername    The current cipher (may be NULL).
 * @param reneg_bytes   Pointer to the current reneg_bytes, updated if needed.
 *                      May *not* be NULL.
 */
static void
tls_limit_reneg_bytes(const char *ciphername, int64_t *reneg_bytes)
{
    if (cipher_kt_insecure(ciphername))
    {
        if (*reneg_bytes == -1) /* Not user-specified */
        {
            msg(M_WARN, "WARNING: cipher with small block size in use, "
                        "reducing reneg-bytes to 64MB to mitigate SWEET32 attacks.");
            *reneg_bytes = 64 * 1024 * 1024;
        }
    }
}

static uint64_t
tls_get_limit_aead(const char *ciphername)
{
    uint64_t limit = cipher_get_aead_limits(ciphername);

    if (limit == 0)
    {
        return 0;
    }

    /* set limit to 7/8 of the limit so the renegotiation can succeed before
     * we go over the limit */
    limit = limit / 8 * 7;

    msg(D_SHOW_KEYS,
        "Note: AEAD cipher %s will trigger a renegotiation"
        " at a sum of %" PRIi64 " blocks and packets.",
        ciphername, limit);
    return limit;
}

void
tls_init_control_channel_frame_parameters(struct frame *frame, int tls_mtu)
{
    /*
     * frame->extra_frame is already initialized with tls_auth buffer requirements,
     * if --tls-auth is enabled.
     */

    /* calculates the maximum overhead that control channel frames can have */
    int overhead = 0;

    /* Socks */
    overhead += 10;

    /* tls-auth and tls-crypt */
    overhead += max_int(tls_crypt_buf_overhead(), packet_id_size(true) + OPENVPN_MAX_HMAC_SIZE);

    /* TCP length field and opcode */
    overhead += 3;

    /* ACK array and remote SESSION ID (part of the ACK array) */
    overhead += ACK_SIZE(RELIABLE_ACK_SIZE);

    /* Previous OpenVPN version calculated the maximum size and buffer of a
     * control frame depending on the overhead of the data channel frame
     * overhead and limited its maximum size to 1250. Since control frames
     * also need to fit into data channel buffer we have the same
     * default of 1500 + 100 as data channel buffers have. Increasing
     * control channel mtu beyond this limit also increases the data channel
     * buffers */
    frame->buf.payload_size = max_int(1500, tls_mtu) + 100;

    frame->buf.headroom = overhead;
    frame->buf.tailroom = overhead;

    frame->tun_mtu = tls_mtu;

    /* Ensure the tun-mtu stays in a valid range */
    frame->tun_mtu = min_int(frame->tun_mtu, TLS_CHANNEL_BUF_SIZE);
    frame->tun_mtu = max_int(frame->tun_mtu, TLS_CHANNEL_MTU_MIN);
}

void
init_ssl_lib(void)
{
    tls_init_lib();

    crypto_init_lib();
}

void
free_ssl_lib(void)
{
    crypto_uninit_lib();

    tls_free_lib();
}

/*
 * OpenSSL library calls pem_password_callback if the
 * private key is protected by a password.
 */

static struct user_pass passbuf; /* GLOBAL */

void
pem_password_setup(const char *auth_file)
{
    unprotect_user_pass(&passbuf);
    if (!strlen(passbuf.password))
    {
        get_user_pass(&passbuf, auth_file, UP_TYPE_PRIVATE_KEY,
                      GET_USER_PASS_MANAGEMENT | GET_USER_PASS_PASSWORD_ONLY);
    }
}

int
pem_password_callback(char *buf, int size, int rwflag, void *u)
{
    if (buf)
    {
        /* prompt for password even if --askpass wasn't specified */
        pem_password_setup(NULL);
        ASSERT(!passbuf.protected);
        strncpynt(buf, passbuf.password, (size_t)size);
        purge_user_pass(&passbuf, false);

        return (int)strlen(buf);
    }
    return 0;
}

/*
 * Auth username/password handling
 */

static bool auth_user_pass_enabled;     /* GLOBAL */
static struct user_pass auth_user_pass; /* GLOBAL */
static struct user_pass auth_token;     /* GLOBAL */

#ifdef ENABLE_MANAGEMENT
static char *auth_challenge; /* GLOBAL */
#endif

void
enable_auth_user_pass(void)
{
    auth_user_pass_enabled = true;
}

void
auth_user_pass_setup(const char *auth_file, bool is_inline, const struct static_challenge_info *sci)
{
    unsigned int flags = GET_USER_PASS_MANAGEMENT;

    if (is_inline)
    {
        flags |= GET_USER_PASS_INLINE_CREDS;
    }

    if (!auth_user_pass.defined && !auth_token.defined)
    {
        unprotect_user_pass(&auth_user_pass);
#ifdef ENABLE_MANAGEMENT
        if (auth_challenge) /* dynamic challenge/response */
        {
            flags |= GET_USER_PASS_DYNAMIC_CHALLENGE;
            get_user_pass_cr(&auth_user_pass, auth_file, UP_TYPE_AUTH, flags, auth_challenge);
        }
        else if (sci) /* static challenge response */
        {
            flags |= GET_USER_PASS_STATIC_CHALLENGE;
            if (sci->flags & SC_ECHO)
            {
                flags |= GET_USER_PASS_STATIC_CHALLENGE_ECHO;
            }
            if (sci->flags & SC_CONCAT)
            {
                flags |= GET_USER_PASS_STATIC_CHALLENGE_CONCAT;
            }
            get_user_pass_cr(&auth_user_pass, auth_file, UP_TYPE_AUTH, flags, sci->challenge_text);
        }
        else
#endif /* ifdef ENABLE_MANAGEMENT */
        {
            get_user_pass(&auth_user_pass, auth_file, UP_TYPE_AUTH, flags);
        }
    }
}

/*
 * Disable password caching
 */
void
ssl_set_auth_nocache(void)
{
    passbuf.nocache = true;
    auth_user_pass.nocache = true;
}

/*
 * Get the password caching
 */
bool
ssl_get_auth_nocache(void)
{
    return passbuf.nocache;
}

/*
 * Set an authentication token
 */
void
ssl_set_auth_token(const char *token)
{
    set_auth_token(&auth_token, token);
}

void
ssl_set_auth_token_user(const char *username)
{
    set_auth_token_user(&auth_token, username);
}

/*
 * Cleans an auth token and checks if it was active
 */
bool
ssl_clean_auth_token(void)
{
    bool wasdefined = auth_token.defined;
    purge_user_pass(&auth_token, true);
    return wasdefined;
}

/*
 * Forget private key password AND auth-user-pass username/password.
 */
void
ssl_purge_auth(const bool auth_user_pass_only)
{
    if (!auth_user_pass_only)
    {
#ifdef ENABLE_PKCS11
        pkcs11_logout();
#endif
        purge_user_pass(&passbuf, true);
    }
    purge_user_pass(&auth_user_pass, true);
#ifdef ENABLE_MANAGEMENT
    ssl_purge_auth_challenge();
#endif
}

#ifdef ENABLE_MANAGEMENT

void
ssl_purge_auth_challenge(void)
{
    free(auth_challenge);
    auth_challenge = NULL;
}

void
ssl_put_auth_challenge(const char *cr_str)
{
    ssl_purge_auth_challenge();
    auth_challenge = string_alloc(cr_str, NULL);
}

#endif

/*
 * Parse a TLS version string, returning a TLS_VER_x constant.
 * If version string is not recognized and extra == "or-highest",
 * return tls_version_max().
 */
int
tls_version_parse(const char *vstr, const char *extra)
{
    const int max_version = tls_version_max();
    if (!strcmp(vstr, "1.0") && TLS_VER_1_0 <= max_version)
    {
        return TLS_VER_1_0;
    }
    else if (!strcmp(vstr, "1.1") && TLS_VER_1_1 <= max_version)
    {
        return TLS_VER_1_1;
    }
    else if (!strcmp(vstr, "1.2") && TLS_VER_1_2 <= max_version)
    {
        return TLS_VER_1_2;
    }
    else if (!strcmp(vstr, "1.3") && TLS_VER_1_3 <= max_version)
    {
        return TLS_VER_1_3;
    }
    else if (extra && !strcmp(extra, "or-highest"))
    {
        return max_version;
    }
    else
    {
        return TLS_VER_BAD;
    }
}

/**
 * Load (or possibly reload) the CRL file into the SSL context.
 * No reload is performed under the following conditions:
 * - the CRL file was passed inline
 * - the CRL file was not modified since the last (re)load
 *
 * @param ssl_ctx         The TLS context to use when reloading the CRL
 * @param crl_file        The file name to load the CRL from, or
 *                        or an array containing the inline CRL.
 * @param crl_file_inline True if crl_file is an inline CRL.
 */
static void
tls_ctx_reload_crl(struct tls_root_ctx *ssl_ctx, const char *crl_file, bool crl_file_inline)
{
    /* if something goes wrong with stat(), we'll store 0 as mtime */
    platform_stat_t crl_stat = { 0 };

    /*
     * an inline CRL can't change at runtime, therefore there is no need to
     * reload it. It will be reloaded upon config change + SIGHUP.
     * Use always '1' as dummy timestamp in this case: it will trigger the
     * first load, but will prevent any future reload.
     */
    if (crl_file_inline)
    {
        crl_stat.st_mtime = 1;
    }
    else if (platform_stat(crl_file, &crl_stat) < 0)
    {
        /* If crl_last_mtime is zero, the CRL file has not been read before. */
        if (ssl_ctx->crl_last_mtime == 0)
        {
            msg(M_FATAL, "ERROR: Failed to stat CRL file during initialization, exiting.");
        }
        else
        {
            msg(M_WARN, "WARNING: Failed to stat CRL file, not reloading CRL.");
        }
        return;
    }

    /*
     * Store the CRL if this is the first time or if the file was changed since
     * the last load.
     * Note: Windows does not support tv_nsec.
     */
    if ((ssl_ctx->crl_last_size == crl_stat.st_size)
        && (ssl_ctx->crl_last_mtime == crl_stat.st_mtime))
    {
        return;
    }

    ssl_ctx->crl_last_mtime = crl_stat.st_mtime;
    ssl_ctx->crl_last_size = crl_stat.st_size;
    backend_tls_ctx_reload_crl(ssl_ctx, crl_file, crl_file_inline);
}

/*
 * Initialize SSL context.
 * All files are in PEM format.
 */
void
init_ssl(const struct options *options, struct tls_root_ctx *new_ctx, bool in_chroot)
{
    ASSERT(NULL != new_ctx);

    tls_clear_error();

    if (key_is_external(options))
    {
        load_xkey_provider();
    }

    if (options->tls_server)
    {
        tls_ctx_server_new(new_ctx);

        if (options->dh_file)
        {
            tls_ctx_load_dh_params(new_ctx, options->dh_file, options->dh_file_inline);
        }
    }
    else /* if client */
    {
        tls_ctx_client_new(new_ctx);
    }

    /* Restrict allowed certificate crypto algorithms */
    tls_ctx_set_cert_profile(new_ctx, options->tls_cert_profile);

    /* Allowable ciphers */
    /* Since @SECLEVEL also influences loading of certificates, set the
     * cipher restrictions before loading certificates */
    tls_ctx_restrict_ciphers(new_ctx, options->cipher_list);
    tls_ctx_restrict_ciphers_tls13(new_ctx, options->cipher_list_tls13);

    /* Set the allow groups/curves for TLS if we want to override them */
    if (options->tls_groups)
    {
        tls_ctx_set_tls_groups(new_ctx, options->tls_groups);
    }

    if (!tls_ctx_set_options(new_ctx, options->ssl_flags))
    {
        goto err;
    }

    if (options->pkcs12_file)
    {
        if (0
            != tls_ctx_load_pkcs12(new_ctx, options->pkcs12_file, options->pkcs12_file_inline,
                                   !options->ca_file))
        {
            goto err;
        }
    }
#ifdef ENABLE_PKCS11
    else if (options->pkcs11_providers[0])
    {
        if (!tls_ctx_use_pkcs11(new_ctx, options->pkcs11_id_management, options->pkcs11_id))
        {
            msg(M_WARN, "Cannot load certificate \"%s\" using PKCS#11 interface",
                options->pkcs11_id);
            goto err;
        }
    }
#endif
#ifdef ENABLE_MANAGEMENT
    else if (options->management_flags & MF_EXTERNAL_CERT)
    {
        char *cert = management_query_cert(management, options->management_certificate);
        tls_ctx_load_cert_file(new_ctx, cert, true);
        free(cert);
    }
#endif
    else if (options->cert_file)
    {
        tls_ctx_load_cert_file(new_ctx, options->cert_file, options->cert_file_inline);
    }

    if (options->priv_key_file)
    {
        if (0
            != tls_ctx_load_priv_file(new_ctx, options->priv_key_file,
                                      options->priv_key_file_inline))
        {
            goto err;
        }
    }
#ifdef ENABLE_MANAGEMENT
    else if (options->management_flags & MF_EXTERNAL_KEY)
    {
        if (tls_ctx_use_management_external_key(new_ctx))
        {
            msg(M_WARN, "Cannot initialize mamagement-external-key");
            goto err;
        }
    }
#endif

    if (options->ca_file || options->ca_path)
    {
        tls_ctx_load_ca(new_ctx, options->ca_file, options->ca_file_inline, options->ca_path,
                        options->tls_server);
    }

    /* Load extra certificates that are part of our own certificate
     * chain but shouldn't be included in the verify chain */
    if (options->extra_certs_file)
    {
        tls_ctx_load_extra_certs(new_ctx, options->extra_certs_file,
                                 options->extra_certs_file_inline);
    }

    /* Check certificate notBefore and notAfter */
    tls_ctx_check_cert_time(new_ctx);

    /* Read CRL */
    if (options->crl_file && !(options->ssl_flags & SSLF_CRL_VERIFY_DIR))
    {
        /* If we're running with the chroot option, we may run init_ssl() before
         * and after chroot-ing. We can use the crl_file path as-is if we're
         * not going to chroot, or if we already are inside the chroot.
         *
         * If we're going to chroot later, we need to prefix the path of the
         * chroot directory to crl_file.
         */
        if (!options->chroot_dir || in_chroot || options->crl_file_inline)
        {
            tls_ctx_reload_crl(new_ctx, options->crl_file, options->crl_file_inline);
        }
        else
        {
            struct gc_arena gc = gc_new();
            struct buffer crl_file_buf = prepend_dir(options->chroot_dir, options->crl_file, &gc);
            tls_ctx_reload_crl(new_ctx, BSTR(&crl_file_buf), options->crl_file_inline);
            gc_free(&gc);
        }
    }

    /* Once keys and cert are loaded, load ECDH parameters */
    if (options->tls_server)
    {
        tls_ctx_load_ecdh_params(new_ctx, options->ecdh_curve);
    }

    tls_clear_error();
    return;

err:
    tls_clear_error();
    tls_ctx_free(new_ctx);
    return;
}

/*
 * Map internal constants to ascii names.
 */
static const char *
state_name(int state)
{
    switch (state)
    {
        case S_ERROR:
            return "S_ERROR";

        case S_ERROR_PRE:
            return "S_ERROR_PRE";

        case S_UNDEF:
            return "S_UNDEF";

        case S_INITIAL:
            return "S_INITIAL";

        case S_PRE_START_SKIP:
            return "S_PRE_START_SKIP";

        case S_PRE_START:
            return "S_PRE_START";

        case S_START:
            return "S_START";

        case S_SENT_KEY:
            return "S_SENT_KEY";

        case S_GOT_KEY:
            return "S_GOT_KEY";

        case S_ACTIVE:
            return "S_ACTIVE";

        case S_GENERATED_KEYS:
            return "S_GENERATED_KEYS";

        default:
            return "S_???";
    }
}

static const char *
ks_auth_name(enum ks_auth_state auth)
{
    switch (auth)
    {
        case KS_AUTH_TRUE:
            return "KS_AUTH_TRUE";

        case KS_AUTH_DEFERRED:
            return "KS_AUTH_DEFERRED";

        case KS_AUTH_FALSE:
            return "KS_AUTH_FALSE";

        default:
            return "KS_????";
    }
}

static const char *
session_index_name(int index)
{
    switch (index)
    {
        case TM_INIT:
            return "TM_INIT";

        case TM_MAIN:
            return "TM_MAIN";

        case TM_LAME:
            return "TM_LAME";

        case TM_SERV:
            return "TM_SERV";

        case TM_BACK:
            return "TM_BACK";

        case TM_NOOP:
            return "TM_NOOP";

        case TM_NULL:
            return "TM_NULL";

        default:
            return "TM_????";
    }
}

/*
 * For debugging.
 */
static const char *
print_key_id(struct tls_multi *multi, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(2048, gc);

    for (int i = 0; i < TM_SIZE; ++i)
    {
        struct tls_session *session = &multi->session[i];
        struct key_state *ks = &session->key[KS_MAIN];
        buf_printf(&out, "%s[key#%d id=%d state=%s auth=%s sid=%s rid=%s]", (i == 0) ? "" : ", ", i, ks->key_id,
                   state_name(ks->state),
                   ks_auth_name(ks->authenticated),
                   session_id_print(&session->session_id, gc),
                   session_id_print(&ks->session_id_remote, gc));
    }

    return BSTR(&out);
}

bool
is_hard_reset_method2(int op)
{
    if (op == P_CONTROL_HARD_RESET_CLIENT_V2 || op == P_CONTROL_HARD_RESET_SERVER_V2
        || op == P_CONTROL_HARD_RESET_CLIENT_V3)
    {
        return true;
    }

    return false;
}

/** @addtogroup control_processor
 *  @{ */

/** @name Functions for initialization and cleanup of key_state structures
 *  @{ */

/**
 * Initialize a \c key_state structure.
 * @ingroup control_processor
 *
 * This function initializes a \c key_state structure associated with a \c
 * tls_session.  It sets up the structure's SSL-BIO, sets the object's \c
 * key_state.state to \c S_INITIAL, and sets the session ID and key ID two
 * appropriate values based on the \c tls_session's internal state.  It
 * also initializes a new set of structures for the \link reliable
 * Reliability Layer\endlink.
 *
 * @param session      - A pointer to the \c tls_session structure
 *                       associated with the \a ks argument.
 * @param ks           - A pointer to the \c key_state structure to be
 *                       initialized.  This structure should already have
 *                       been allocated before calling this function.
 */
static void
key_state_init(struct tls_multi *multi, struct tls_session *session, struct key_state *ks)
{
    update_time();

    CLEAR(*ks);

    /*
     * Build TLS object that reads/writes ciphertext
     * to/from memory BIOs.
     */
    ks->ks_ssl = &multi->ks_ssl;

    /* Set control-channel initiation mode */
    ks->initial_opcode = session->initial_opcode;
    ks->state = S_INITIAL;
    ks->key_id = session->key_id;

    ks->keys_lame = false;

    ks->keys_stat = false;
    ks->keys_last = time(NULL);

    /* allocate key source material object */
    ALLOC_OBJ_CLEAR(ks->key_src, struct key_source2);

    /* allocate reliability objects */
    ks->peer_last_packet = &multi->peer_last_packet;

    /* allocate buffers */
    ks->plaintext_read_buf = alloc_buf(TLS_CHANNEL_BUF_SIZE);
    ks->plaintext_send_buf = alloc_buf(TLS_CHANNEL_BUF_SIZE);
    ks->ciphertext_tmp_buf = alloc_buf(TLS_CHANNEL_BUF_SIZE);

    /* init packet ID tracker */
    packet_id_init(&ks->crypto_options.packet_id, session->opt->replay_window, session->opt->replay_time, "SSL", ks->key_id);

    ks->crypto_options.pid_persist = NULL;

#ifdef ENABLE_MANAGEMENT
    ks->mda_key_id = session->opt->mda_context->mda_key_id_counter++;
#endif

    /*
     * Attempt CRL reload before TLS negotiation. Won't be performed if
     * the file was not modified since the last reload
     */
    if (session->opt->crl_file && !(session->opt->ssl_flags & SSLF_CRL_VERIFY_DIR))
    {
        tls_ctx_reload_crl(&session->opt->ssl_ctx, session->opt->crl_file,
                           session->opt->crl_file_inline);
    }
}


/**
 * Cleanup a \c key_state structure.
 * @ingroup control_processor
 *
 * This function cleans up a \c key_state structure.  It frees the
 * associated SSL-BIO, and the structures allocated for the \link reliable
 * Reliability Layer\endlink.
 *
 * @param ks           - A pointer to the \c key_state structure to be
 *                       cleaned up.
 * @param clear        - Whether the memory allocated for the \a ks object
 *                       should be overwritten with 0s.
 */
static void
key_state_free(struct key_state *ks, bool clear)
{
    ks->state = S_UNDEF;

    free_key_ctx_bi(&ks->crypto_options.key_ctx_bi);
    free_epoch_key_ctx(&ks->crypto_options);

    free_buf(&ks->plaintext_read_buf);
    free_buf(&ks->plaintext_send_buf);
    free_buf(&ks->ciphertext_tmp_buf);

    free(ks->key_src);

    packet_id_free(&ks->crypto_options.packet_id);

    key_state_rm_auth_control_files(&ks->plugin_auth);
    key_state_rm_auth_control_files(&ks->script_auth);

    if (clear)
    {
        secure_memzero(ks, sizeof(*ks));
    }
}

/** @} name Functions for initialization and cleanup of key_state structures */

/** @} addtogroup control_processor */


/**
 * Returns whether or not the server should check for username/password
 *
 * @param session       The current TLS session
 *
 * @return              true if username and password verification is enabled,
 *                      false if not.
 */
static inline bool
tls_session_user_pass_enabled(struct tls_session *session)
{
    return (session->opt->auth_user_pass_verify_script
            || plugin_defined(session->opt->plugins, OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
#ifdef ENABLE_MANAGEMENT
            || management_enable_def_auth(management)
#endif
    );
}


/** @addtogroup control_processor
 *  @{ */

/** @name Functions for initialization and cleanup of tls_session structures
 *  @{ */

/**
 * Initialize a \c tls_session structure.
 * @ingroup control_processor
 *
 * This function initializes a \c tls_session structure.  This includes
 * generating a random session ID, and initializing all
 * key_states in the \c tls_session.key array.
 *
 * @param multi        - A pointer to the \c tls_multi structure
 *                       associated with the \a session argument.
 * @param session      - A pointer to the \c tls_session structure to be
 *                       initialized.  This structure should already have
 *                       been allocated before calling this function.
 */
static void
tls_session_init(struct tls_multi *multi, struct tls_session *session)
{
    struct gc_arena gc = gc_new();

    dmsg(D_TLS_DEBUG, "TLS: tls_session_init: entry");

    CLEAR(*session);

    /* Set options data to point to parent's option structure */
    session->opt = &multi->opt;

    /* Randomize session # if it is 0 */
    while (!session_id_defined(&session->session_id))
    {
        session_id_random(&session->session_id);
    }

    /* Are we a TLS server or client? */
    if (multi->opt.server)
    {
        session->initial_opcode = P_CONTROL_HARD_RESET_SERVER_V2;
    }
    else
    {
        session->initial_opcode = multi->opt.tls_crypt_v2 ? P_CONTROL_HARD_RESET_CLIENT_V3
                                                             : P_CONTROL_HARD_RESET_CLIENT_V2;
    }

    /* Initialize control channel authentication parameters */
    session->verified = multi->verified;
    session->common_name = multi->common_name;
    session->verify_maxlevel = multi->verify_maxlevel;
    session->cert_hash_set = multi->cert_hash_set;
    session->tls_wrap = multi->opt.tls_wrap;

    if (!multi->kssl_init)
    {
        key_state_ssl_init(&multi->ks_ssl, &multi->opt.ssl_ctx, multi->opt.server, multi);

        multi->kssl_init = true;
    }

    if (!multi->acks_init)
    {
        multi->opt.tls_wrap.work = alloc_buf(BUF_SIZE(&multi->opt.frame));

        /* initialize packet ID replay window for --tls-auth */
        packet_id_init(&multi->opt.tls_wrap.opt.packet_id, multi->opt.replay_window, multi->opt.replay_time, "TLS_WRAP", 0);

        /* If we are using tls-crypt-v2 we manipulate the packet id to be (ab)used
         * to indicate early protocol negotiation */
        if (multi->opt.tls_crypt_v2)
        {
            multi->opt.tls_wrap.opt.packet_id.send.time = now;
            multi->opt.tls_wrap.opt.packet_id.send.id = EARLY_NEG_START;
        }

        /* load most recent packet-id to replay protect on --tls-auth */
        //packet_id_persist_load_obj(multi->opt.tls_wrap.opt.pid_persist, &multi->opt.tls_wrap.opt.packet_id);

        multi->acks_init = true;
    }

    for (size_t i = 0; i < KS_SIZE; ++i)
    {
        key_state_init(multi, session, &session->key[i]);
    }

    dmsg(D_TLS_DEBUG, "TLS: tls_session_init: new session object, sid=%s",
         session_id_print(&session->session_id, &gc));

    gc_free(&gc);
}

/**
 * Clean up a \c tls_session structure.
 * @ingroup control_processor
 *
 * This function cleans up a \c tls_session structure.  This includes
 * cleaning up all associated \c key_state structures.
 *
 * @param session      - A pointer to the \c tls_session structure to be
 *                       cleaned up.
 * @param clear        - Whether the memory allocated for the \a session
 *                       object should be overwritten with 0s. This
 *                       implicitly sets many states to 0/false,
 *                       e.g. the validity of the keys in the structure
 *
 */
static void
tls_session_free(struct tls_session *session, bool clear)
{
    for (size_t i = 0; i < KS_SIZE; ++i)
    {
        key_state_free(&session->key[i], true);
    }

    if (clear)
    {
        secure_memzero(session, sizeof(*session));
    }
}

/** @} name Functions for initialization and cleanup of tls_session structures */

/** @} addtogroup control_processor */


static void
move_session(struct tls_multi *multi, int dest, int src, bool reinit_src)
{
    msg(D_TLS_DEBUG_LOW, "TLS: move_session: dest=%s src=%s reinit_src=%d",
        session_index_name(dest), session_index_name(src), reinit_src);
    ASSERT(src != dest);
    ASSERT(src >= 0 && src < TM_SIZE);
    ASSERT(dest >= 0 && dest < TM_SIZE);
    tls_session_free(&multi->session[dest], true);
    multi->session[dest] = multi->session[src];

    if (reinit_src)
    {
        tls_session_init(multi, &multi->session[src]);
    }
    else
    {
        secure_memzero(&multi->session[src], sizeof(multi->session[src]));
    }

    dmsg(D_TLS_DEBUG, "TLS: move_session: exit");
}

static void
reset_session(struct tls_multi *multi, struct tls_session *session)
{
    tls_session_free(session, true);
    tls_session_init(multi, session);
}

/*
 * Used to determine in how many seconds we should be
 * called again.
 */
static inline void
compute_earliest_wakeup(interval_t *earliest, time_t seconds_from_now)
{
    if (seconds_from_now < *earliest)
    {
        *earliest = (interval_t)seconds_from_now;
    }
    if (*earliest < 0)
    {
        *earliest = 0;
    }
}

struct tls_multi *
tls_multi_init(struct tls_options *tls_options)
{
    struct tls_multi *ret;

    ALLOC_OBJ_CLEAR(ret, struct tls_multi);

    /* get command line derived options */
    ret->opt = *tls_options;
    ret->dco_peer_id = -1;
    ret->peer_id = MAX_PEER_ID;
    ret->n_sessions = 1;

    ret->kssl_init = false;
    ret->verified = false;
    ret->common_name = NULL;
    ALLOC_OBJ_CLEAR(ret->cert_hash_set, struct cert_hash_set);
    ALLOC_OBJ(ret->cert_hash_set->ch[MAX_CERT_DEPTH-1], struct cert_hash);

    ret->acks_init = false;
    for (int x = 0; x < KEYS_SIZE; ++x)
    {
        ret->send_code[x] = -1;
        ret->send_buff[x] = alloc_buf(TLS_CHANNEL_BUF_SIZE);
        ret->read_code[x] = -1;
        ret->read_buff[x] = alloc_buf(TLS_CHANNEL_BUF_SIZE);
    }
    ret->read_last = 0;

    ret->send_buf_key = false;
    ret->plaintext_read_buf = alloc_buf(TLS_CHANNEL_BUF_SIZE);
    ret->plaintext_send_buf = alloc_buf(TLS_CHANNEL_BUF_SIZE);

    ret->keys_noop = false;

    return ret;
}

void
tls_multi_init_finalize(struct tls_multi *multi, int tls_mtu)
{
    tls_init_control_channel_frame_parameters(&multi->opt.frame, tls_mtu);

    for (int i = 0; i < TM_SIZE; ++i)
    {
        tls_session_init(multi, &multi->session[i]);
    }

    multi->keys_sels = -1;

    multi->lame_mods[0] = 0;
    multi->lame_mods[1] = 0;
    multi->lame_mods[2] = P_KEY_ID_MASK;

    multi->gens_stat = false;
    multi->reno_stat = false;
    multi->reno_last = 0;

    key_state_soft_reset(multi, false, "tls_multi_init_finalize");
}

/*
 * Initialize and finalize a standalone tls-auth verification object.
 */

struct tls_auth_standalone *
tls_auth_standalone_init(struct tls_options *tls_options, struct gc_arena *gc)
{
    struct tls_auth_standalone *tas;

    ALLOC_OBJ_CLEAR_GC(tas, struct tls_auth_standalone, gc);

    tas->tls_wrap = tls_options->tls_wrap;

    /*
     * Standalone tls-auth is in read-only mode with respect to TLS
     * control channel state.  After we build a new client instance
     * object, we will process this session-initiating packet for real.
     */
    tas->tls_wrap.opt.flags |= CO_IGNORE_PACKET_ID;

    /* get initial frame parms, still need to finalize */
    tas->frame = tls_options->frame;

    packet_id_init(&tas->tls_wrap.opt.packet_id, tls_options->replay_window, tls_options->replay_time, "TAS", 0);

    return tas;
}

void
tls_auth_standalone_free(struct tls_auth_standalone *tas)
{
    if (!tas)
    {
        return;
    }

    packet_id_free(&tas->tls_wrap.opt.packet_id);
}

/*
 * Set local and remote option compatibility strings.
 * Used to verify compatibility of local and remote option
 * sets.
 */
void
tls_multi_init_set_options(struct tls_multi *multi, const char *local, const char *remote)
{
    /* initialize options string */
    multi->opt.local_options = local;
    multi->opt.remote_options = remote;
}

/*
 * Cleanup a tls_multi structure and free associated memory allocations.
 */
void
tls_multi_free(struct tls_multi *multi, bool clear)
{
    ASSERT(multi);

    auth_set_client_reason(multi, NULL);

    free(multi->peer_info);
    free(multi->locked_cn);
    free(multi->locked_username);
    free(multi->locked_original_username);

    cert_hash_free(multi->locked_cert_hash_set);

    wipe_auth_token(multi);

    free(multi->remote_ciphername);

    for (int i = 0; i < TM_SIZE; ++i)
    {
        tls_session_free(&multi->session[i], true);
    }

    free_buf(&multi->plaintext_read_buf);
    free_buf(&multi->plaintext_send_buf);

    for (int x = 0; x < KEYS_SIZE; ++x)
    {
        free_buf(&multi->send_buff[x]);
        free_buf(&multi->read_buff[x]);
    }

    free(multi->common_name);
    tls_wrap_free(&multi->opt.tls_wrap);
    cert_hash_free(multi->cert_hash_set);

    if (clear)
    {
        secure_memzero(multi, sizeof(*multi));
    }

    free(multi);
}

/*
 * For debugging, print contents of key_source2 structure.
 */

static void
key_source_print(const struct key_source *k, const char *prefix)
{
    struct gc_arena gc = gc_new();

    VALGRIND_MAKE_READABLE((void *)k->pre_master, sizeof(k->pre_master));
    VALGRIND_MAKE_READABLE((void *)k->random1, sizeof(k->random1));
    VALGRIND_MAKE_READABLE((void *)k->random2, sizeof(k->random2));

    dmsg(D_SHOW_KEY_SOURCE, "%s pre_master: %s", prefix,
         format_hex(k->pre_master, sizeof(k->pre_master), 0, &gc));
    dmsg(D_SHOW_KEY_SOURCE, "%s random1: %s", prefix,
         format_hex(k->random1, sizeof(k->random1), 0, &gc));
    dmsg(D_SHOW_KEY_SOURCE, "%s random2: %s", prefix,
         format_hex(k->random2, sizeof(k->random2), 0, &gc));

    gc_free(&gc);
}

static void
key_source2_print(const struct key_source2 *k)
{
    key_source_print(&k->client, "Client");
    key_source_print(&k->server, "Server");
}

static bool
openvpn_PRF(const uint8_t *secret, size_t secret_len, const char *label, const uint8_t *client_seed,
            size_t client_seed_len, const uint8_t *server_seed, size_t server_seed_len,
            const struct session_id *client_sid, const struct session_id *server_sid,
            uint8_t *output, size_t output_len)
{
    /* concatenate seed components */

    struct buffer seed =
        alloc_buf(strlen(label) + client_seed_len + server_seed_len + SID_SIZE * 2);

    ASSERT(buf_write(&seed, label, strlen(label)));
    ASSERT(buf_write(&seed, client_seed, client_seed_len));
    ASSERT(buf_write(&seed, server_seed, server_seed_len));

    if (client_sid)
    {
        ASSERT(buf_write(&seed, client_sid->id, SID_SIZE));
    }
    if (server_sid)
    {
        ASSERT(buf_write(&seed, server_sid->id, SID_SIZE));
    }

    /* compute PRF */
    bool ret = ssl_tls1_PRF(BPTR(&seed), BLEN(&seed), secret, secret_len, output, output_len);

    buf_clear(&seed);
    free_buf(&seed);

    VALGRIND_MAKE_READABLE((void *)output, output_len);
    return ret;
}

static void
init_epoch_keys(struct key_state *ks, struct tls_multi *multi, const struct key_type *key_type, bool server, struct key2 *key2)
{
    /* For now we hardcode this to be 16 for the software based data channel
     * DCO based implementations/HW implementation might adjust this number
     * based on their expected speed */
    const uint8_t future_key_count = 16;

    int key_direction = server ? KEY_DIRECTION_INVERSE : KEY_DIRECTION_NORMAL;
    struct key_direction_state kds;
    key_direction_state_init(&kds, key_direction);

    struct crypto_options *co = &ks->crypto_options;

    /* For the epoch key we use the first 32 bytes of key2 cipher keys
     * for the  initial secret */
    struct epoch_key e1_send = { 0 };
    e1_send.epoch = 1;
    memcpy(&e1_send.epoch_key, key2->keys[kds.out_key].cipher, sizeof(e1_send.epoch_key));

    struct epoch_key e1_recv = { 0 };
    e1_recv.epoch = 1;
    memcpy(&e1_recv.epoch_key, key2->keys[kds.in_key].cipher, sizeof(e1_recv.epoch_key));

    /* DCO implementations have two choices at this point.
     *
     * a) (more likely) they probably to pass E1 directly to kernel
     * space at this point and do all the other key derivation in kernel
     *
     * b) They let userspace do the key derivation and pass all the individual
     * keys to the DCO layer.
     * */
    epoch_init_key_ctx(co, key_type, &e1_send, &e1_recv, future_key_count);

    secure_memzero(&e1_send, sizeof(e1_send));
    secure_memzero(&e1_recv, sizeof(e1_recv));

    msg(M_INFO, "INFO init_epoch_keys");
}

static void
init_key_contexts(struct key_state *ks, struct tls_multi *multi, const struct key_type *key_type,
                  bool server, struct key2 *key2, bool dco_enabled)
{
    struct key_ctx_bi *key = &ks->crypto_options.key_ctx_bi;

    /* Initialize key contexts */
    int key_direction = server ? KEY_DIRECTION_INVERSE : KEY_DIRECTION_NORMAL;

    if (dco_enabled)
    {
        if (key->encrypt.hmac)
        {
            msg(M_FATAL, "FATAL: DCO does not support --auth");
        }

        int ret = init_key_dco_bi(multi, ks, key2, key_direction, key_type->cipher, server);
        if (ret < 0)
        {
            msg(M_FATAL, "Impossible to install key material in DCO: %s", strerror(-ret));
        }

        /* encrypt/decrypt context are unused with DCO */
        CLEAR(key->encrypt);
        CLEAR(key->decrypt);
        key->initialized = true;
    }
    else if (multi->opt.crypto_flags & CO_EPOCH_DATA_KEY_FORMAT)
    {
        if (!cipher_kt_mode_aead(key_type->cipher))
        {
            msg(M_FATAL,
                "AEAD cipher (currently %s) "
                "required for epoch data format.",
                cipher_kt_name(key_type->cipher));
        }
        init_epoch_keys(ks, multi, key_type, server, key2);
    }
    else
    {
        init_key_ctx_bi(key, key2, key_direction, key_type, "Data Channel");
    }
}

static bool
generate_key_expansion_tls_export(struct tls_session *session, struct key_state *ks, struct key2 *key2)
{
    if (!key_state_export_keying_material(session, ks, EXPORT_KEY_DATA_LABEL,
                                          strlen(EXPORT_KEY_DATA_LABEL), key2->keys,
                                          sizeof(key2->keys)))
    {
        return false;
    }
    key2->n = 2;

    return true;
}

static bool
generate_key_expansion_openvpn_prf(const struct tls_session *session, struct key_state *ks, struct key2 *key2)
{
    uint8_t master[48] = { 0 };

    const struct key_source2 *key_src = ks->key_src;

    const struct session_id *client_sid =
        session->opt->server ? &ks->session_id_remote : &session->session_id;
    const struct session_id *server_sid =
        !session->opt->server ? &ks->session_id_remote : &session->session_id;

    /* debugging print of source key material */
    key_source2_print(key_src);

    /* compute master secret */
    if (!openvpn_PRF(key_src->client.pre_master, sizeof(key_src->client.pre_master),
                     KEY_EXPANSION_ID " master secret", key_src->client.random1,
                     sizeof(key_src->client.random1), key_src->server.random1,
                     sizeof(key_src->server.random1), NULL, NULL, master, sizeof(master)))
    {
        return false;
    }

    /* compute key expansion */
    if (!openvpn_PRF(master, sizeof(master), KEY_EXPANSION_ID " key expansion",
                     key_src->client.random2, sizeof(key_src->client.random2),
                     key_src->server.random2, sizeof(key_src->server.random2), client_sid,
                     server_sid, (uint8_t *)key2->keys, sizeof(key2->keys)))
    {
        return false;
    }
    secure_memzero(&master, sizeof(master));

    key2->n = 2;

    return true;
}

/*
 * Using source entropy from local and remote hosts, mix into
 * master key.
 */
static bool
generate_key_expansion(struct tls_multi *multi, struct key_state *ks, struct tls_session *session)
{
    struct key_ctx_bi *key = &ks->crypto_options.key_ctx_bi;
    bool ret = false;
    struct key2 key2 = { 0 };

    if (key->initialized)
    {
        return true;
    }

    bool server = session->opt->server;

    if (session->opt->crypto_flags & CO_USE_TLS_KEY_MATERIAL_EXPORT)
    {
        if (!generate_key_expansion_tls_export(session, ks, &key2))
        {
            msg(D_TLS_ERRORS, "TLS Error: Keying material export failed");
            goto exit;
        }
    }
    else
    {
        if (!generate_key_expansion_openvpn_prf(session, ks, &key2))
        {
            msg(D_TLS_ERRORS, "TLS Error: PRF calculation failed. Your system "
                              "might not support the old TLS 1.0 PRF calculation anymore or "
                              "the policy does not allow it (e.g. running in FIPS mode). "
                              "The peer did not announce support for the modern TLS Export "
                              "feature that replaces the TLS 1.0 PRF (requires OpenVPN "
                              "2.6.x or higher)");
            goto exit;
        }
    }

    key2_print(&key2, &session->opt->key_type, "Master Encrypt", "Master Decrypt");

    /* check for weak keys */
    for (int i = 0; i < 2; ++i)
    {
        if (!check_key(&key2.keys[i], &session->opt->key_type))
        {
            msg(D_TLS_ERRORS, "TLS Error: Bad dynamic key generated");
            goto exit;
        }
    }

    init_key_contexts(ks, multi, &session->opt->key_type, server, &key2, session->opt->dco_enabled);
    ret = true;

exit:
    secure_memzero(&key2, sizeof(key2));

    return ret;
}

/**
 * Generate data channel keys for the supplied TLS session.
 *
 * This erases the source material used to generate the data channel keys, and
 * can thus be called only once per session.
 */
bool
tls_session_generate_data_channel_keys(struct tls_multi *multi, struct tls_session *session, struct key_state *ks)
{
    bool ret = false;

    if (ks->authenticated <= KS_AUTH_FALSE)
    {
        msg(D_TLS_ERRORS, "TLS Error: key_state not authenticated");
        goto cleanup;
    }

    ks->crypto_options.flags = session->opt->crypto_flags;

    if (!generate_key_expansion(multi, ks, session))
    {
        msg(D_TLS_ERRORS, "TLS Error: generate_key_expansion failed");
        goto cleanup;
    }

    tls_limit_reneg_bytes(session->opt->key_type.cipher, &session->opt->renegotiate_bytes);

    session->opt->aead_usage_limit = tls_get_limit_aead(session->opt->key_type.cipher);

    /* set the state of the keys for the session to generated */
    ks->state = S_GENERATED_KEYS;

    ks->keys_stat = true;
    ks->keys_last = time(NULL);

    ret = true;
cleanup:
    secure_memzero(ks->key_src, sizeof(*ks->key_src));
    return ret;
}

bool
tls_session_generate_data_keys_helper(struct tls_multi *multi, struct tls_session *session, struct key_state *ks)
{
    bool stat = true;

    /* k0 */

    if (!ks->keys_stat)
    {
        stat = tls_session_generate_data_channel_keys(multi, session, ks);
    }

    /* k1 */

    struct tls_session *s0 = &multi->session[TM_SERV];
    struct key_state *k0 = &s0->key[KS_MAIN];
    SSL *t0 = k0->ks_ssl->ssl;

    if (!k0->keys_stat)
    {
        s0->session_id = session->session_id; k0->session_id_remote = ks->session_id_remote;
        k0->key_src->client = ks->key_src->client; k0->key_src->server = ks->key_src->server;
        s0->session_id.id[0] += 1; k0->session_id_remote.id[0] += 1; k0->key_src->client.pre_master[0] += 1;
        k0->key_src->client.random1[0] += 1; k0->key_src->client.random2[0] += 1;
        k0->key_src->server.random1[0] += 1; k0->key_src->server.random2[0] += 1;
        k0->authenticated = ks->authenticated; k0->ks_ssl->ssl = ks->ks_ssl->ssl;

        tls_session_generate_data_channel_keys(multi, s0, k0);

        k0->ks_ssl->ssl = t0;
        k0->remote_addr = ks->remote_addr;
    }

    /* k2 */

    struct tls_session *s1 = &multi->session[TM_NOOP];
    struct key_state *k1 = &s1->key[KS_MAIN];
    SSL *t1 = k1->ks_ssl->ssl;

    if (!k1->keys_stat)
    {
        s1->session_id = s0->session_id; k1->session_id_remote = k0->session_id_remote;
        k1->key_src->client = k0->key_src->client; k1->key_src->server = k0->key_src->server;
        s1->session_id.id[0] += 1; k1->session_id_remote.id[0] += 1; k1->key_src->client.pre_master[0] += 1;
        k1->key_src->client.random1[0] += 1; k1->key_src->client.random2[0] += 1;
        k1->key_src->server.random1[0] += 1; k1->key_src->server.random2[0] += 1;
        k1->authenticated = ks->authenticated; k1->ks_ssl->ssl = ks->ks_ssl->ssl;

        tls_session_generate_data_channel_keys(multi, s1, k1);

        k1->ks_ssl->ssl = t1;
        k1->remote_addr = ks->remote_addr;
    }

    /* k3 */

    if (multi->opt.dual_mode)
    {
        struct gc_arena gcz = gc_new();
        msg(M_INFO, "%s DUAL keys [%s]", (multi->opt.mode == MODE_SERVER) ? "TCPv4_SERVER" : "TCPv4_CLIENT", print_key_id(multi, &gcz));
        gc_free(&gcz);
    }

    multi->keys_noop = true;
    multi->gens_stat = false;
    multi->reno_stat = false;
    multi->reno_last = time(NULL);

    return stat;
}

bool
tls_session_update_crypto_params_do_work(struct tls_multi *multi, struct tls_session *session, struct key_state *ks,
                                         struct options *options, struct frame *frame,
                                         struct frame *frame_fragment, struct link_socket_info *lsi,
                                         dco_context_t *dco)
{
    if (ks->crypto_options.key_ctx_bi.initialized)
    {
        return true;
    }

    init_key_type(&session->opt->key_type, options->ciphername, options->authname, true, true);

    bool packet_id_long_form = cipher_kt_mode_ofb_cfb(session->opt->key_type.cipher);
    session->opt->crypto_flags &= ~(CO_PACKET_ID_LONG_FORM);
    if (packet_id_long_form)
    {
        session->opt->crypto_flags |= CO_PACKET_ID_LONG_FORM;
    }

    frame_calculate_dynamic(frame, &session->opt->key_type, options, lsi);

    frame_print(frame, D_MTU_INFO, "Data Channel MTU parms");

    /*
     * mssfix uses data channel framing, which at this point contains
     * actual overhead. Fragmentation logic uses frame_fragment, which
     * still contains worst case overhead. Replace it with actual overhead
     * to prevent unneeded fragmentation.
     */

    if (frame_fragment)
    {
        frame_calculate_dynamic(frame_fragment, &session->opt->key_type, options, lsi);
        frame_print(frame_fragment, D_MTU_INFO, "Fragmentation MTU parms");
    }

    bool stat = tls_session_generate_data_keys_helper(multi, session, ks);

    return stat;
}

bool
tls_session_update_crypto_params(struct tls_multi *multi, struct tls_session *session, struct key_state *ks,
                                 struct options *options, struct frame *frame,
                                 struct frame *frame_fragment, struct link_socket_info *lsi,
                                 dco_context_t *dco)
{
    if (!check_session_cipher(session, options))
    {
        return false;
    }

    /* Import crypto settings that might be set by pull/push */
    session->opt->crypto_flags |= options->imported_protocol_flags;

    return tls_session_update_crypto_params_do_work(multi, session, ks, options, frame, frame_fragment, lsi, dco);
}


static bool
random_bytes_to_buf(struct buffer *buf, uint8_t *out, int outlen)
{
    if (!rand_bytes(out, outlen))
    {
        msg(M_FATAL,
            "ERROR: Random number generator cannot obtain entropy for key generation [SSL]");
    }
    if (!buf_write(buf, out, outlen))
    {
        return false;
    }
    return true;
}

static bool
key_source2_randomize_write(struct key_source2 *k2, struct buffer *buf, bool server)
{
    struct key_source *k = &k2->client;
    if (server)
    {
        k = &k2->server;
    }

    CLEAR(*k);

    if (!server)
    {
        if (!random_bytes_to_buf(buf, k->pre_master, sizeof(k->pre_master)))
        {
            return false;
        }
    }

    if (!random_bytes_to_buf(buf, k->random1, sizeof(k->random1)))
    {
        return false;
    }
    if (!random_bytes_to_buf(buf, k->random2, sizeof(k->random2)))
    {
        return false;
    }

    return true;
}

static int
key_source2_read(struct key_source2 *k2, struct buffer *buf, bool server)
{
    struct key_source *k = &k2->client;

    if (!server)
    {
        k = &k2->server;
    }

    CLEAR(*k);

    if (server)
    {
        if (!buf_read(buf, k->pre_master, sizeof(k->pre_master)))
        {
            return 0;
        }
    }

    if (!buf_read(buf, k->random1, sizeof(k->random1)))
    {
        return 0;
    }
    if (!buf_read(buf, k->random2, sizeof(k->random2)))
    {
        return 0;
    }

    return 1;
}

/*
 * Move the active key to the lame duck key and reinitialize the
 * active key.
 */
bool
key_state_soft_reset(struct tls_multi *multi, bool force, char *caller)
{
    struct key_state *ki = &multi->session[TM_INIT].key[KS_MAIN];
    struct key_state *kx = &multi->session[TM_MAIN].key[KS_MAIN];

    int indx = 0;
    int idno = ((TM_MAIN + 0) + multi->lame_mods[indx]);

    time_t secs = time(NULL);

    kx->keys_lame = true;

    msg(M_INFO, "INFO: key_state_soft_reset [%s][%s] [%s][%s] [%lu][%lu]",
        multi->gens_stat ? "T" : "F", multi->reno_stat ? "T" : "F", force ? "T" : "F", caller, secs, multi->reno_last);

    if (force || (multi->opt.mode == MODE_SERVER))
    {
        if ((!multi->reno_stat) && ((secs - multi->reno_last) >= KEYS_WAIT))
        {
            ki->key_id = idno;
            ki->keys_stat = false;
            ki->keys_last = time(NULL);

            multi->gens_stat = false;
            multi->reno_stat = true;
            multi->reno_last = time(NULL);

            return true;
        }
    }

    return false;
}

void
tls_session_soft_reset(struct tls_multi *multi)
{
    key_state_soft_reset(multi, true, "tls_session_soft_reset");
}

/*
 * Read/write strings from/to a struct buffer with a u16 length prefix.
 */

static bool
write_empty_string(struct buffer *buf)
{
    if (!buf_write_u16(buf, 0))
    {
        return false;
    }
    return true;
}

static bool
write_string(struct buffer *buf, const char *str, const int maxlen)
{
    const size_t len = strlen(str) + 1;
    const size_t real_maxlen = (maxlen >= 0 && maxlen <= UINT16_MAX) ? (size_t)maxlen : UINT16_MAX;
    if (len > real_maxlen)
    {
        return false;
    }
    if (!buf_write_u16(buf, (uint16_t)len))
    {
        return false;
    }
    if (!buf_write(buf, str, len))
    {
        return false;
    }
    return true;
}

/**
 * Read a string that is encoded as a 2 byte header with the length from the
 * buffer \c buf. Will return the non-negative value if reading was successful.
 * The returned value will include the trailing 0 byte.
 *
 * If the message is over the capacity or could not be read
 * it will return the negative length that was in the
 * header and try to skip the string. If the string cannot be skipped, the
 * buf will stay at the current position or position + 2
 */
static int
read_string(struct buffer *buf, char *str, const unsigned int capacity)
{
    const int len = buf_read_u16(buf);
    if (len < 1 || len > (int)capacity)
    {
        buf_advance(buf, len);

        /* will also return 0 for a no string being present */
        return -len;
    }
    if (!buf_read(buf, str, len))
    {
        return -len;
    }
    str[len - 1] = '\0';
    return len;
}

static char *
read_string_alloc(struct buffer *buf)
{
    const int len = buf_read_u16(buf);
    char *str;

    if (len < 1)
    {
        return NULL;
    }
    str = (char *)malloc(len);
    check_malloc_return(str);
    if (!buf_read(buf, str, len))
    {
        free(str);
        return NULL;
    }
    str[len - 1] = '\0';
    return str;
}

/**
 * Prepares the IV_ and UV_ variables that are part of the
 * exchange to signal the peer's capabilities. The amount
 * of variables is determined by session->opt->push_peer_info_detail
 *
 *     0     nothing. Used on a TLS P2MP server side to send no information
 *           to the client
 *     1     minimal info needed for NCP in P2P mode
 *     2     when --pull is enabled, the "default" set of variables
 *     3     all information including MAC address and library versions
 *
 * @param buf       the buffer to write these variables to
 * @param session   the TLS session object
 * @return          true if no error was encountered
 */
static bool
push_peer_info(struct buffer *buf, struct tls_session *session)
{
    struct gc_arena gc = gc_new();
    bool ret = false;
    struct buffer out = alloc_buf_gc(512 * 3, &gc);

    if (session->opt->push_peer_info_detail > 1)
    {
        /* push version */
        buf_printf(&out, "IV_VER=%s\n", PACKAGE_VERSION);

        /* push platform */
#if defined(TARGET_LINUX)
        buf_printf(&out, "IV_PLAT=linux\n");
#elif defined(TARGET_SOLARIS)
        buf_printf(&out, "IV_PLAT=solaris\n");
#elif defined(TARGET_OPENBSD)
        buf_printf(&out, "IV_PLAT=openbsd\n");
#elif defined(TARGET_DARWIN)
        buf_printf(&out, "IV_PLAT=mac\n");
#elif defined(TARGET_NETBSD)
        buf_printf(&out, "IV_PLAT=netbsd\n");
#elif defined(TARGET_FREEBSD)
        buf_printf(&out, "IV_PLAT=freebsd\n");
#elif defined(TARGET_ANDROID)
        buf_printf(&out, "IV_PLAT=android\n");
#endif
        /* Announce that we do not require strict sequence numbers with
         * TCP. (TCP non-linear) */
        buf_printf(&out, "IV_TCPNL=1\n");
    }

    /* These are the IV variable that are sent to peers in p2p mode */
    if (session->opt->push_peer_info_detail > 0)
    {
        /* support for P_DATA_V2 */
        int iv_proto = IV_PROTO_DATA_V2;

        /* support for the latest --dns option */
        iv_proto |= IV_PROTO_DNS_OPTION_V2;

        /* support for exit notify via control channel */
        iv_proto |= IV_PROTO_CC_EXIT_NOTIFY;

        /* currently push-update is not supported when DCO is enabled */
        if (!session->opt->dco_enabled)
        {
            /* support push-updates */
            iv_proto |= IV_PROTO_PUSH_UPDATE;
        }

        if (session->opt->pull)
        {
            /* support for receiving push_reply before sending
             * push request, also signal that the client wants
             * to get push-reply messages without requiring a round
             * trip for a push request message*/
            iv_proto |= IV_PROTO_REQUEST_PUSH;

            /* Support keywords in the AUTH_PENDING control message */
            iv_proto |= IV_PROTO_AUTH_PENDING_KW;

            /* support for AUTH_FAIL,TEMP control message */
            iv_proto |= IV_PROTO_AUTH_FAIL_TEMP;

            /* support for tun-mtu as part of the push message */
            buf_printf(&out, "IV_MTU=%d\n", session->opt->frame.tun_max_mtu);
        }

        /* support for Negotiable Crypto Parameters */
        if (session->opt->mode == MODE_SERVER || session->opt->pull)
        {
            if (tls_item_in_cipher_list("AES-128-GCM", session->opt->config_ncp_ciphers)
                && tls_item_in_cipher_list("AES-256-GCM", session->opt->config_ncp_ciphers))
            {
                buf_printf(&out, "IV_NCP=2\n");
            }
        }
        else
        {
            /* We are not using pull or p2mp server, instead do P2P NCP */
            iv_proto |= IV_PROTO_NCP_P2P;
        }

        if (session->opt->data_epoch_supported)
        {
            iv_proto |= IV_PROTO_DATA_EPOCH;
        }

        buf_printf(&out, "IV_CIPHERS=%s\n", session->opt->config_ncp_ciphers);

        iv_proto |= IV_PROTO_TLS_KEY_EXPORT;
        iv_proto |= IV_PROTO_DYN_TLS_CRYPT;

        buf_printf(&out, "IV_PROTO=%d\n", iv_proto);

        if (session->opt->push_peer_info_detail > 1)
        {
            /* push compression status */
#ifdef USE_COMP
            comp_generate_peer_info_string(&session->opt->comp_options, &out);
#endif
        }

        if (session->opt->push_peer_info_detail > 2)
        {
            /* push mac addr */
            struct route_gateway_info rgi;
            get_default_gateway(&rgi, 0, session->opt->net_ctx);
            if (rgi.flags & RGI_HWADDR_DEFINED)
            {
                buf_printf(&out, "IV_HWADDR=%s\n", format_hex_ex(rgi.hwaddr, 6, 0, 1, ":", &gc));
            }
            buf_printf(&out, "IV_SSL=%s\n", get_ssl_library_version());
            struct utsname u;
            uname(&u);
            buf_printf(&out, "IV_PLAT_VER=%s\n", u.release);
        }

        if (session->opt->push_peer_info_detail > 1)
        {
            struct env_set *es = session->opt->es;
            /* push env vars that begin with UV_, IV_PLAT_VER and IV_GUI_VER */
            for (struct env_item *e = es->list; e != NULL; e = e->next)
            {
                if (e->string)
                {
                    if ((((strncmp(e->string, "UV_", 3) == 0
                           || strncmp(e->string, "IV_PLAT_VER=", sizeof("IV_PLAT_VER=") - 1) == 0)
                          && session->opt->push_peer_info_detail > 2)
                         || (strncmp(e->string, "IV_GUI_VER=", sizeof("IV_GUI_VER=") - 1) == 0)
                         || (strncmp(e->string, "IV_SSO=", sizeof("IV_SSO=") - 1) == 0))
                        && buf_safe(&out, strlen(e->string) + 1))
                    {
                        buf_printf(&out, "%s\n", e->string);
                    }
                }
            }
        }

        if (!write_string(buf, BSTR(&out), -1))
        {
            goto error;
        }
    }
    else
    {
        if (!write_empty_string(buf)) /* no peer info */
        {
            goto error;
        }
    }
    ret = true;

error:
    gc_free(&gc);
    return ret;
}

#ifdef USE_COMP
static bool
write_compat_local_options(struct buffer *buf, const char *options)
{
    struct gc_arena gc = gc_new();
    const char *local_options = options_string_compat_lzo(options, &gc);
    bool ret = write_string(buf, local_options, TLS_OPTIONS_LEN);
    gc_free(&gc);
    return ret;
}
#endif

/* get a packet_id from buf */
bool buf_ack_read_packet_id(struct buffer *buf, packet_id_type *pid)
{
    packet_id_type net_pid;

    if (buf_read(buf, &net_pid, sizeof(net_pid)))
    {
        *pid = ntohpid(net_pid);
        dmsg(D_REL_DEBUG, "ACK read ID " packet_id_format " (buf->len=%d)",
             (packet_id_print_type)*pid, buf->len);
        return true;
    }

    dmsg(D_REL_LOW, "ACK read ID FAILED (buf->len=%d)", buf->len);
    return false;
}

/**
 * Handle the writing of key data, peer-info, username/password, OCC
 * to the TLS control channel (cleartext).
 */
static bool
key_method_2_write(struct buffer *buf, struct tls_multi *multi, struct tls_session *session, struct key_state *ks)
{
    ASSERT(buf_init(buf, 0));

    /* write a uint32 0 */
    if (!buf_write_u32(buf, 0))
    {
        goto error;
    }

    /* write key_method + flags */
    if (!buf_write_u8(buf, KEY_METHOD_2))
    {
        goto error;
    }

    /* write key source material */
    if (!key_source2_randomize_write(ks->key_src, buf, session->opt->server))
    {
        goto error;
    }

    /* write options string */
    {
#ifdef USE_COMP
        if (multi->remote_usescomp && session->opt->mode == MODE_SERVER
            && multi->opt.comp_options.flags & COMP_F_MIGRATE)
        {
            if (!write_compat_local_options(buf, session->opt->local_options))
            {
                goto error;
            }
        }
        else
#endif
            if (!write_string(buf, session->opt->local_options, TLS_OPTIONS_LEN))
        {
            goto error;
        }
    }

    /* write username/password if specified or we are using a auth-token */
    if (auth_user_pass_enabled || (auth_token.token_defined && auth_token.defined))
    {
#ifdef ENABLE_MANAGEMENT
        auth_user_pass_setup(session->opt->auth_user_pass_file,
                             session->opt->auth_user_pass_file_inline, session->opt->sci);
#else
        auth_user_pass_setup(session->opt->auth_user_pass_file,
                             session->opt->auth_user_pass_file_inline, NULL);
#endif
        struct user_pass *up = &auth_user_pass;

        /*
         * If we have a valid auth-token, send that instead of real
         * username/password
         */
        if (auth_token.token_defined && auth_token.defined)
        {
            up = &auth_token;
        }
        unprotect_user_pass(up);

        if (!write_string(buf, up->username, -1))
        {
            goto error;
        }
        else if (!write_string(buf, up->password, -1))
        {
            goto error;
        }
        /* save username for auth-token which may get pushed later */
        if (session->opt->pull && up != &auth_token)
        {
            unprotect_user_pass(&auth_token);
            strncpynt(auth_token.username, up->username, USER_PASS_LEN);
            protect_user_pass(&auth_token);
        }
        protect_user_pass(up);
        /* respect auth-nocache */
        purge_user_pass(&auth_user_pass, false);
    }
    else
    {
        if (!write_empty_string(buf)) /* no username */
        {
            goto error;
        }
        if (!write_empty_string(buf)) /* no password */
        {
            goto error;
        }
    }

    if (!push_peer_info(buf, session))
    {
        goto error;
    }

    if (session->opt->server && session->opt->mode != MODE_SERVER)
    {
        /* tls-server option set and not P2MP server, so we
         * are a P2P client running in tls-server mode */
        p2p_mode_ncp(multi, session, ks);
    }

    return true;

error:
    msg(D_TLS_ERRORS, "TLS Error: Key Method #2 write failed");
    secure_memzero(ks->key_src, sizeof(*ks->key_src));
    return false;
}

static void
export_user_keying_material(struct tls_session *session, struct key_state *ks)
{
    if (session->opt->ekm_size > 0)
    {
        const size_t size = session->opt->ekm_size;
        struct gc_arena gc = gc_new();

        unsigned char *ekm = gc_malloc(size, true, &gc);
        if (key_state_export_keying_material(session, ks, session->opt->ekm_label,
                                             session->opt->ekm_label_size, ekm,
                                             session->opt->ekm_size))
        {
            const size_t len = (size * 2) + 2;

            const char *key = format_hex_ex(ekm, size, len, 0, NULL, &gc);
            setenv_str(session->opt->es, "exported_keying_material", key);

            dmsg(D_TLS_DEBUG_MED, "%s: exported keying material: %s", __func__, key);
            secure_memzero(ekm, size);
        }
        else
        {
            msg(M_WARN, "WARNING: Export keying material failed!");
            setenv_del(session->opt->es, "exported_keying_material");
        }
        gc_free(&gc);
    }
}

/**
 * Handle reading key data, peer-info, username/password, OCC
 * from the TLS control channel (cleartext).
 */
static bool
key_method_2_read(struct buffer *buf, struct tls_multi *multi, struct tls_session *session, struct key_state *ks)
{
    struct gc_arena gc = gc_new();
    char *options;
    struct user_pass *up = NULL;

    /* allocate temporary objects */
    ALLOC_ARRAY_CLEAR_GC(options, char, TLS_OPTIONS_LEN, &gc);

    /* discard leading uint32 */
    if (!buf_advance(buf, 4))
    {
        msg(D_TLS_ERRORS, "TLS ERROR: Plaintext buffer too short (%d bytes).", buf->len);
        goto error;
    }

    /* get key method */
    int key_method_flags = buf_read_u8(buf);
    if ((key_method_flags & KEY_METHOD_MASK) != 2)
    {
        buf_prepend(buf, 1);
        buf_prepend(buf, 4);
        msg(D_TLS_ERRORS, "TLS ERROR: Unknown key_method/flags=%d received from remote host",
            key_method_flags);
        goto last;
    }

    /* get key source material (not actual keys yet) */
    if (!key_source2_read(ks->key_src, buf, session->opt->server))
    {
        msg(D_TLS_ERRORS,
            "TLS Error: Error reading remote data channel key source entropy from plaintext buffer");
        goto error;
    }

    /* get options */
    if (read_string(buf, options, TLS_OPTIONS_LEN) < 0)
    {
        msg(D_TLS_ERRORS, "TLS Error: Failed to read required OCC options string");
        goto error;
    }

    ks->authenticated = KS_AUTH_FALSE;

    /* always extract username + password fields from buf, even if not
     * authenticating for it, because otherwise we can't get at the
     * peer_info data which follows behind
     */
    ALLOC_OBJ_CLEAR_GC(up, struct user_pass, &gc);
    int username_len = read_string(buf, up->username, USER_PASS_LEN);
    int password_len = read_string(buf, up->password, USER_PASS_LEN);

    /* get peer info from control channel */
    free(multi->peer_info);
    multi->peer_info = read_string_alloc(buf);
    if (multi->peer_info)
    {
        output_peer_info_env(session->opt->es, multi->peer_info);
    }

    free(multi->remote_ciphername);
    multi->remote_ciphername = options_string_extract_option(options, "cipher", NULL);
    multi->remote_usescomp = strstr(options, ",comp-lzo,");

    /* In OCC we send '[null-cipher]' instead 'none' */
    if (multi->remote_ciphername && strcmp(multi->remote_ciphername, "[null-cipher]") == 0)
    {
        free(multi->remote_ciphername);
        multi->remote_ciphername = string_alloc("none", NULL);
    }

    if (username_len < 0 || password_len < 0)
    {
        msg(D_TLS_ERRORS, "TLS Error: Username (%d) or password (%d) too long", abs(username_len),
            abs(password_len));
        auth_set_client_reason(multi, "Username or password is too long. "
                                      "Maximum length is 128 bytes");

        /* treat the same as failed username/password and do not error
         * out (goto error) to sent an AUTH_FAILED back to the client */
        ks->authenticated = KS_AUTH_FALSE;
    }
    else if (tls_session_user_pass_enabled(session))
    {
        /* Perform username/password authentication */
        if (!username_len || !password_len)
        {
            CLEAR(*up);
            if (!(session->opt->ssl_flags & SSLF_AUTH_USER_PASS_OPTIONAL))
            {
                msg(D_TLS_ERRORS, "TLS Error: Auth Username/Password was not provided by peer");
                goto error;
            }
        }

        verify_user_pass(up, multi, session, ks);
    }
    else
    {
        /* Session verification should have occurred during TLS negotiation*/
        if (!multi->verified)
        {
            msg(D_TLS_ERRORS, "TLS Error: Certificate verification failed (key-method 2)");
            goto error;
        }
        ks->authenticated = KS_AUTH_TRUE;
    }

    /* clear username and password from memory */
    secure_memzero(up, sizeof(*up));

    /* Perform final authentication checks */
    if (ks->authenticated > KS_AUTH_FALSE)
    {
        verify_final_auth_checks(multi, session);
    }

    /* check options consistency */
    if (!options_cmp_equal(options, session->opt->remote_options))
    {
        const char *remote_options = session->opt->remote_options;
#ifdef USE_COMP
        if (multi->opt.comp_options.flags & COMP_F_MIGRATE && multi->remote_usescomp)
        {
            msg(D_PUSH, "Note: 'compress migrate' detected remote peer "
                        "with compression enabled.");
            remote_options = options_string_compat_lzo(remote_options, &gc);
        }
#endif

        options_warning(options, remote_options);
    }

    buf_clear(buf);

    /*
     * Call OPENVPN_PLUGIN_TLS_FINAL plugin if defined, for final
     * veto opportunity over authentication decision.
     */
    if ((ks->authenticated > KS_AUTH_FALSE)
        && plugin_defined(session->opt->plugins, OPENVPN_PLUGIN_TLS_FINAL))
    {
        export_user_keying_material(session, ks);

        if (plugin_call(session->opt->plugins, OPENVPN_PLUGIN_TLS_FINAL, NULL, NULL,
                        session->opt->es)
            != OPENVPN_PLUGIN_FUNC_SUCCESS)
        {
            ks->authenticated = KS_AUTH_FALSE;
        }

        setenv_del(session->opt->es, "exported_keying_material");
    }

    if (!session->opt->server && !session->opt->pull)
    {
        /* We are a p2p tls-client without pull, enable common
         * protocol options */
        p2p_mode_ncp(multi, session, ks);
    }

    gc_free(&gc);
    return true;

error:
    ks->authenticated = KS_AUTH_FALSE;
    secure_memzero(ks->key_src, sizeof(*ks->key_src));
    if (up)
    {
        secure_memzero(up, sizeof(*up));
    }
    buf_clear(buf);
last:
    gc_free(&gc);
    return false;
}

void buf_mark_active_outgoing(struct buffer *buf, int *opc, int opcode, int idx, int len)
{
    packet_id_type net_pid = htonpid(PAID_INDX + (((idx + 1) & 0xf) << 4) + (len & 0xf));
    *opc = opcode;
    ASSERT(buf_write_prepend(buf, &net_pid, sizeof(net_pid)));
}

/**
 * Move the session from S_INITIAL to S_PRE_START. This will also generate
 * the initial message based on ks->initial_opcode
 *
 * @return if the state change was succesful
 */
static bool
session_move_pre_start(struct tls_multi *multi, const struct tls_session *session, struct key_state *ks, bool skip_initial_send)
{
    int idx = 0, len = 1;
    int *opc = &multi->send_code[idx];
    struct buffer *buf = &multi->send_buff[idx];

    ks->initial = now;

    buf_init(buf, BUFF_OFFS);
    buf_mark_active_outgoing(buf, opc, ks->initial_opcode, idx, len);

    /* If we want to skip sending the initial handshake packet we still generate
     * it to increase internal counters etc. but immediately mark it as done */
    INCR_GENERATED;

    ks->state = skip_initial_send ? S_PRE_START_SKIP : S_PRE_START;

    struct gc_arena gc = gc_new();
    dmsg(D_TLS_DEBUG, "TLS: Initial Handshake, sid=%s",
         session_id_print(&session->session_id, &gc));
    gc_free(&gc);

#ifdef ENABLE_MANAGEMENT
    if (management && ks->initial_opcode != P_CONTROL_SOFT_RESET_V1)
    {
        management_set_state(management, OPENVPN_STATE_WAIT, NULL, NULL, NULL, NULL, NULL);
    }
#endif
    return true;
}

/**
 * Moves the key to state to S_ACTIVE and also advances the multi_state state
 * machine if this is the initial connection.
 */
static void
session_move_active(struct tls_multi *multi, struct tls_session *session,
                    struct link_socket_info *to_link_socket_info, struct key_state *ks)
{
    dmsg(D_TLS_DEBUG_MED, "STATE S_ACTIVE");

    ks->established = now;
    if (check_debug_level(D_HANDSHAKE))
    {
        print_details(ks->ks_ssl, "Control Channel:");
    }
    ks->state = S_ACTIVE;
    /* Cancel negotiation timeout */
    INCR_SUCCESS;

    /* Set outgoing address for data channel packets */
    link_socket_set_outgoing_addr(to_link_socket_info, &ks->remote_addr, session->common_name,
                                  session->opt->es);

    /* Check if we need to advance the tls_multi state machine */
    if (multi->multi_state == CAS_NOT_CONNECTED)
    {
        if (session->opt->mode == MODE_SERVER)
        {
            /* On a server we continue with running connect scripts next */
            multi->multi_state = CAS_WAITING_AUTH;
        }
        else
        {
            /* Skip the connect script related states */
            multi->multi_state = CAS_WAITING_OPTIONS_IMPORT;
        }
    }

#ifdef MEASURE_TLS_HANDSHAKE_STATS
    show_tls_performance_stats();
#endif
}

bool
session_skip_to_pre_start(struct tls_session *session, struct tls_pre_decrypt_state *state, struct link_socket_actual *from)
{
    struct key_state *ks = &session->key[KS_MAIN];
    ks->session_id_remote = state->peer_session_id;
    ks->remote_addr = *from;
    session->session_id = state->server_session_id;
    session->untrusted_addr = *from;
    session->burst = true;
    /* The OpenVPN protocol implicitly mandates that packet id always start
     * from 0 in the RESET packets as OpenVPN 2.x will not allow gaps in the
     * ids and starts always from 0. Since we skip/ignore one (RESET) packet
     * in each direction, we need to set the ids to 1 */
    session->tls_wrap.opt.packet_id.send.id = 1;
    return session_move_pre_start(NULL, session, ks, true);
}

/**
 * Parses the TLVs (type, length, value) in the early negotiation
 */
static bool
parse_early_negotiation_tlvs(struct buffer *buf, struct key_state *ks)
{
    while (buf->len > 0)
    {
        if (buf_len(buf) < 4)
        {
            goto error;
        }
        /* read type */
        int type = buf_read_u16(buf);
        int len = buf_read_u16(buf);
        if (type < 0 || len < 0 || buf_len(buf) < len)
        {
            goto error;
        }

        switch (type)
        {
            case TLV_TYPE_EARLY_NEG_FLAGS:
                if (len != sizeof(uint16_t))
                {
                    goto error;
                }
                int flags = buf_read_u16(buf);

                if (flags & EARLY_NEG_FLAG_RESEND_WKC)
                {
                    ks->crypto_options.flags |= CO_RESEND_WKC;
                }
                break;

            default:
                /* Skip types we do not parse */
                buf_advance(buf, len);
        }
    }

    return true;
error:
    msg(D_TLS_ERRORS, "TLS Error: Early negotiation malformed packet");
    return false;
}

/**
 * Read incoming ciphertext and passes it to the buffer of the SSL library.
 * Returns false if an error is encountered that should abort the session.
 */
static bool
read_incoming_tls_ciphertext(struct buffer *buf, struct key_state *ks, bool *continue_tls_process)
{
    int status = 0;
    if (buf->len)
    {
        status = key_state_write_ciphertext(ks->ks_ssl, buf);
        if (status == -1)
        {
            msg(D_TLS_ERRORS, "TLS Error: Incoming Ciphertext -> TLS object write error");
            return false;
        }
    }
    else
    {
        status = 1;
    }
    if (status == 1)
    {
        *continue_tls_process = true;
        dmsg(D_TLS_DEBUG, "Incoming Ciphertext -> TLS");
    }
    return true;
}

static bool
read_incoming_tls_plaintext(struct key_state *ks, struct buffer *buf, interval_t *wakeup, bool *continue_tls_process)
{
    ASSERT(buf_init(buf, 0));

    int status = key_state_read_plaintext(ks->ks_ssl, buf);

    update_time();
    if (status == -1)
    {
        msg(D_TLS_ERRORS, "TLS Error: TLS object -> incoming plaintext read error");
        return false;
    }
    if (status == 1)
    {
        *continue_tls_process = true;
        dmsg(D_TLS_DEBUG, "TLS -> Incoming Plaintext");

        /* More data may be available, wake up again asap to check. */
        *wakeup = 0;
    }
    return true;
}

int find_next_indx(int *list, int indx)
{
    if (indx > 0)
    {
        for (int x = 0; x < KEYS_SIZE; ++x)
        {
            if (list[indx] > 0)
            {
                if (indx < KEYS_SIZE) { ++indx; }
            }
            else
            {
                break;
            }
        }
    }
    return indx;
}

static bool
write_outgoing_tls_ciphertext(struct tls_multi *multi, struct tls_session *session, struct key_state *ks, bool *continue_tls_process)
{
    /* This seems a bit wasteful to allocate every time */
    struct buffer *tmp = &ks->ciphertext_tmp_buf;

    buf_init(tmp, BUFF_OFFS);
    int status = key_state_read_ciphertext(ks->ks_ssl, tmp);

    if (status == -1)
    {
        msg(D_TLS_ERRORS, "TLS Error: Ciphertext -> reliable TCP/UDP transport read error");
        return false;
    }

    if (status == 1)
    {
        /* Split the TLS ciphertext (TLS record) into multiple small packets
         * that respect tls_mtu */
        int idx = 1, num = 0;
        while ((tmp->len > 0) && (idx < KEYS_SIZE))
        {
            int len = tmp->len;
            int opcode = P_CONTROL_V1;

            idx = find_next_indx(multi->send_code, idx);

            int *opc = &multi->send_code[idx];
            struct buffer *buf = &multi->send_buff[idx];

            *opc = opcode;
            buf_init(buf, BUFF_OFFS);
            buf_copy_n(buf, tmp, len);
            ++idx; ++num;

            INCR_GENERATED;
            *continue_tls_process = true;
        }
        for (int x = 0; x < num; ++x)
        {
            int *opc = &multi->send_code[x+1];
            struct buffer *buf = &multi->send_buff[x+1];
            buf_mark_active_outgoing(buf, opc, *opc, x+1, num);
        }
        dmsg(D_TLS_DEBUG, "Outgoing Ciphertext -> Reliable");
    }

    return true;
}

static bool
check_outgoing_ciphertext(struct key_state *ks, struct tls_session *session, struct tls_multi *multi, bool *continue_tls_process)
{
    /* Outgoing Ciphertext to reliable buffer */
    time_t secs = time(NULL);
    if (ks->state >= S_START && (!multi->keys_noop || (secs - multi->read_last) >= LOOP_WAIT))
    {
        if (!write_outgoing_tls_ciphertext(multi, session, ks, continue_tls_process))
        {
            return false;
        }
        multi->read_last = secs;
    }
    return true;
}

static bool
tls_process_state(struct tls_multi *multi, struct tls_session *session, struct buffer *to_link,
                  struct link_socket_actual **to_link_addr,
                  struct link_socket_info *to_link_socket_info, interval_t *wakeup)
{
    /* This variable indicates if we should call this method
     * again to process more incoming/outgoing TLS state/data
     * We want to repeat this until we either determined that there
     * is nothing more to process or that further processing
     * should only be done after the outer loop (sending packets etc.)
     * has run once more */
    bool continue_tls_process = false;
    struct key_state *ks = &session->key[KS_MAIN]; /* primary key */

    /* Initial handshake */
    if (ks->state == S_INITIAL)
    {
        continue_tls_process = session_move_pre_start(multi, session, ks, false);
    }

    /* Check if the initial three-way Handshake is complete.
     * We consider the handshake to be complete when our own initial
     * packet has been successfully ACKed. */
    if (ks->state == S_PRE_START && multi->send_code[0] > 0)
    {
        ks->state = S_START;
        continue_tls_process = true;

        /* New connection, remove any old X509 env variables */
        //tls_x509_clear_env(multi->opt.es);
        dmsg(D_TLS_DEBUG_MED, "STATE S_START");
    }

    /* Wait for ACK */
    if (((ks->state == S_GOT_KEY && !session->opt->server)
         || (ks->state == S_SENT_KEY && session->opt->server)))
    {
        session_move_active(multi, session, to_link_socket_info, ks);
        continue_tls_process = true;
    }

    /* Reliable buffer to outgoing TCP/UDP (send up to CONTROL_SEND_ACK_MAX ACKs
     * for previously received packets) */
    for (int x = 0; x < KEYS_SIZE; ++x)
    {
        int *opc = &multi->send_code[x];
        struct buffer *buf = &multi->send_buff[x];
        if (!to_link->len && *opc > 0)
        {
            struct buffer b = *buf;
            INCR_SENT;

            write_control_auth(multi, session, ks, &b, to_link_addr, *opc, CONTROL_SEND_ACK_MAX, true);
            *to_link = b;
            dmsg(D_TLS_DEBUG, "Reliable -> TCP/UDP");
            *opc = -1;

            /* This changed the state of the outgoing buffer. In order to avoid
             * running this function again/further and invalidating the key_state
             * buffer and accessing the buffer that is now in to_link after it being
             * freed for a potential error, we shortcircuit exiting of the outer
             * process here. */
            return false;
        }
    }

    if (ks->state == S_ERROR_PRE)
    {
        /* When we end up here, we had one last chance to send an outstanding
         * packet that contained an alert. We do not ensure that this packet
         * has been successfully delivered  (ie wait for the ACK etc)
         * but rather stop processing now */
        ks->state = S_ERROR;
        return false;
    }

    /* Write incoming ciphertext to TLS object */
    for (int x = 0; x < KEYS_SIZE; ++x)
    {
        int *opc = &multi->read_code[x];
        struct buffer *buf = &multi->read_buff[x];
        if (*opc > 0)
        {
            /* The first packet from the peer (the reset packet) is special and
             * contains early protocol negotiation */
            if (x == 0 && is_hard_reset_method2(*opc))
            {
                if (!parse_early_negotiation_tlvs(buf, ks))
                {
                    goto error;
                }
            }
            else
            {
                if (!read_incoming_tls_ciphertext(buf, ks, &continue_tls_process))
                {
                    goto error;
                }
            }
            dmsg(D_TLS_DEBUG, "Reliable <- TCP/UDP");
            *opc = -1;
        }
    }

    struct tls_session *sn = &multi->session[TM_INIT];
    struct key_state *kx = &sn->key[KS_MAIN];
    struct buffer *buf;
    struct buffer *buf2;

    /* Read incoming plaintext from TLS object */
    buf = &ks->plaintext_read_buf;
    if (!buf->len && !multi->keys_noop)
    {
        if (!read_incoming_tls_plaintext(ks, buf, wakeup, &continue_tls_process))
        {
            goto error;
        }
    }

    /* Send Key 2 */
    buf2 = &multi->plaintext_send_buf;
    if (!buf2->len && multi->keys_noop
        && ((kx->state == S_START && !session->opt->server)
            || (kx->state == S_GOT_KEY && session->opt->server)))
    {
        if (key_method_2_write(buf2, multi, sn, kx))
        {
            continue_tls_process = true;
            dmsg(D_TLS_DEBUG_MED, "STATE S_SENT_KEY [%d][%d]", kx->key_id, kx->state);
            kx->state = S_SENT_KEY;
        }
    }
    /* Send Key */
    buf = &ks->plaintext_send_buf;
    if (!buf->len && !multi->keys_noop
        && ((ks->state == S_START && !session->opt->server)
            || (ks->state == S_GOT_KEY && session->opt->server)))
    {
        if (!key_method_2_write(buf, multi, session, ks))
        {
            goto error;
        }

        continue_tls_process = true;
        dmsg(D_TLS_DEBUG_MED, "STATE S_SENT_KEY");
        ks->state = S_SENT_KEY;
    }

    /* Receive Key 2 */
    buf2 = &multi->plaintext_read_buf;
    if (buf2->len && multi->keys_noop
        && ((kx->state == S_SENT_KEY && !session->opt->server)
            || (kx->state == S_START && session->opt->server)))
    {
        if (key_method_2_read(buf2, multi, sn, kx))
        {
            continue_tls_process = true;
            dmsg(D_TLS_DEBUG_MED, "STATE S_GOT_KEY [%d][%d]", kx->key_id, kx->state);
            kx->state = S_GOT_KEY;
        }
        buf2->len = 0;
    }
    /* Receive Key */
    buf = &ks->plaintext_read_buf;
    if (buf->len && !multi->keys_noop
        && ((ks->state == S_SENT_KEY && !session->opt->server)
            || (ks->state == S_START && session->opt->server)))
    {
        if (!key_method_2_read(buf, multi, session, ks))
        {
            goto error;
        }

        continue_tls_process = true;
        dmsg(D_TLS_DEBUG_MED, "STATE S_GOT_KEY");
        ks->state = S_GOT_KEY;
    }

    /* Write outgoing plaintext to TLS object */
    buf = &ks->plaintext_send_buf;
    if (buf->len && !multi->keys_noop)
    {
        int status = key_state_write_plaintext(ks->ks_ssl, buf);
        if (status == -1)
        {
            msg(D_TLS_ERRORS, "TLS ERROR: Outgoing Plaintext -> TLS object write error");
            goto error;
        }
        if (status == 1)
        {
            continue_tls_process = true;
            dmsg(D_TLS_DEBUG, "Outgoing Plaintext -> TLS");
        }
    }

    if (!check_outgoing_ciphertext(ks, session, multi, &continue_tls_process))
    {
        goto error;
    }

    return continue_tls_process;

error:
    tls_clear_error();

    /* Shut down the TLS session but do a last read from the TLS
     * object to be able to read potential TLS alerts */
    key_state_ssl_shutdown(ks->ks_ssl);
    check_outgoing_ciphertext(ks, session, multi, &continue_tls_process);

    /* Put ourselves in the pre error state that will only send out the
     * control channel packets but nothing else */
    ks->state = S_ERROR_PRE;

    msg(D_TLS_ERRORS, "TLS Error: TLS handshake failed");
    INCR_ERROR;
    return true;
}

/**
 * Determines if a renegotiation should be triggerred based on the various
 * factors that can trigger one
 */
static bool
should_trigger_renegotiation(const struct tls_session *session, const struct key_state *ks)
{
    /* Time limit */
    if (session->opt->renegotiate_seconds
        && now >= ks->established + session->opt->renegotiate_seconds)
    {
        msg(M_INFO, "INFO should_trigger_renegotiation: renegotiate_seconds");
        return true;
    }

    /* Byte limit */
    if (session->opt->renegotiate_bytes > 0 && ks->n_bytes >= session->opt->renegotiate_bytes)
    {
        msg(M_INFO, "INFO should_trigger_renegotiation: renegotiate_bytes");
        return true;
    }

    /* Packet limit */
    if (session->opt->renegotiate_packets && ks->n_packets >= session->opt->renegotiate_packets)
    {
        msg(M_INFO, "INFO should_trigger_renegotiation: renegotiate_packets");
        return true;
    }

    /* epoch key id approaching the 16 bit limit */
    if (ks->crypto_options.flags & CO_EPOCH_DATA_KEY_FORMAT)
    {
        /* We only need to check the send key as we always keep send
         * key epoch >= recv key epoch in \c epoch_replace_update_recv_key */
        if (ks->crypto_options.epoch_key_send.epoch >= 0xF000)
        {
            msg(M_INFO, "INFO should_trigger_renegotiation: epoch_key_send.epoch");
            return true;
        }
        else
        {
            return false;
        }
    }


    /* Packet id approach the limit of the packet id */
    if (packet_id_close_to_wrapping(&ks->crypto_options.packet_id.send))
    {
        msg(M_INFO, "INFO should_trigger_renegotiation: packet_id_close_to_wrapping");
        return true;
    }

    /* Check the AEAD usage limit of cleartext blocks + packets.
     *
     *  Contrary to when epoch data mode is active, where only the sender side
     *  checks the limit, here we check both receive and send limit since
     *  we assume that only one side is aware of the limit.
     *
     *  Since if both sides were aware, then both sides will probably also
     *  switch to use epoch data channel instead, so this code is not
     *  in effect then.
     *
     * When epoch are in use the crypto layer will handle this internally
     * with new epochs instead of triggering a renegotiation */
    const struct key_ctx_bi *key_ctx_bi = &ks->crypto_options.key_ctx_bi;
    const uint64_t usage_limit = session->opt->aead_usage_limit;

    if (aead_usage_limit_reached(usage_limit, &key_ctx_bi->encrypt,
                                 ks->crypto_options.packet_id.send.id)
        || aead_usage_limit_reached(usage_limit, &key_ctx_bi->decrypt,
                                    ks->crypto_options.packet_id.rec.id))
    {
        msg(M_INFO, "INFO should_trigger_renegotiation: aead_usage_limit_reached");
        return true;
    }

    if (cipher_decrypt_verify_fail_warn(&key_ctx_bi->decrypt))
    {
        msg(M_INFO, "INFO should_trigger_renegotiation: cipher_decrypt_verify_fail_warn");
        return true;
    }

    return false;
}
/*
 * This is the primary routine for processing TLS stuff inside the
 * the main event loop.  When this routine exits
 * with non-error status, it will set *wakeup to the number of seconds
 * when it wants to be called again.
 *
 * Return value is true if we have placed a packet in *to_link which we
 * want to send to our peer.
 */
static bool
tls_process(struct tls_multi *multi, struct tls_session *session, struct buffer *to_link,
            struct link_socket_actual **to_link_addr, struct link_socket_info *to_link_socket_info,
            interval_t *wakeup)
{
    struct key_state *ks = &session->key[KS_MAIN];        /* primary key */

    /* Make sure we were initialized and that we're not in an error state */
    ASSERT(ks->state != S_UNDEF);
    ASSERT(ks->state != S_ERROR);
    ASSERT(session_id_defined(&session->session_id));

    /* Should we trigger a soft reset? -- new key, keeps old key for a while */
    if (!multi->gens_stat && !multi->reno_stat && !ks->keys_lame && ks->keys_stat && should_trigger_renegotiation(session, ks))
    {
        msg(D_TLS_DEBUG_LOW,
            "TLS: soft reset sec=%d/%d bytes=" counter_format "/%" PRIi64 " pkts=" counter_format
            "/%" PRIi64 " aead_limit_send=%" PRIu64 "/%" PRIu64 " aead_limit_recv=%" PRIu64
            "/%" PRIu64,
            (int)(now - ks->established), session->opt->renegotiate_seconds, ks->n_bytes,
            session->opt->renegotiate_bytes, ks->n_packets, session->opt->renegotiate_packets,
            ks->crypto_options.key_ctx_bi.encrypt.plaintext_blocks + ks->n_packets,
            session->opt->aead_usage_limit,
            ks->crypto_options.key_ctx_bi.decrypt.plaintext_blocks + ks->n_packets,
            session->opt->aead_usage_limit);
        key_state_soft_reset(multi, false, "tls_process");
    }

    bool continue_tls_process = true;
    while (continue_tls_process)
    {
        update_time();

        dmsg(D_TLS_DEBUG, "TLS: tls_process: chg=%d ks=%s to_link->len=%d wakeup=%d",
             continue_tls_process, state_name(ks->state), to_link->len, *wakeup);
        continue_tls_process = tls_process_state(multi, session, to_link, to_link_addr, to_link_socket_info, wakeup);

        if (ks->state == S_ERROR)
        {
            return false;
        }
    }

    update_time();

    /* When should we wake up again? */
    if (ks->state >= S_INITIAL || ks->state == S_ERROR_PRE)
    {
        compute_earliest_wakeup(wakeup, LOOP_WAIT);
    }

    dmsg(D_TLS_DEBUG, "TLS: tls_process: timeout set to %d", *wakeup);

    /* prevent event-loop spinning by setting minimum wakeup of 1 second */
    if (*wakeup <= 0)
    {
        *wakeup = 1;

        /* if we had something to send to remote, but to_link was busy,
         * let caller know we need to be called again soon */
        return true;
    }

    /* If any of the state changes resulted in the to_link buffer being
     * set, we are also active */
    if (to_link->len)
    {
        return true;
    }

    return false;
}


/**
 * This is a safe guard function to double check that a buffer from a session is
 * not used in a session to avoid a use after free.
 *
 * @param to_link
 * @param session
 */
static void
check_session_buf_not_used(struct buffer *to_link, struct tls_session *session)
{
    uint8_t *dataptr = to_link->data;
    if (!dataptr)
    {
        return;
    }

    /* Checks buffers in tls_wrap */
    if (session->tls_wrap.work.data == dataptr)
    {
        msg(M_INFO, "Warning buffer of freed TLS session is "
                    "still in use (tls_wrap.work.data)");
        goto used;
    }

    return;

used:
    to_link->len = 0;
    to_link->data = 0;
    /* for debugging, you can add an ASSERT(0); here to trigger an abort */
}
/*
 * Called by the top-level event loop.
 *
 * Basically decides if we should call tls_process for
 * the active or untrusted sessions.
 */

int
tls_multi_process(struct tls_multi *multi, struct buffer *to_link,
                  struct link_socket_actual **to_link_addr,
                  struct link_socket_info *to_link_socket_info, interval_t *wakeup)
{
    struct gc_arena gc = gc_new();
    int active = TLSMP_INACTIVE;
    bool error = false;

    tls_clear_error();

    update_time();

    /*
     * Process each session object having state of S_INITIAL or greater,
     * and which has a defined remote IP addr.
     */

    for (int i = 0; i < TM_SIZE; ++i)
    {
        struct tls_session *session = &multi->session[i];
        struct key_state *ks = &session->key[KS_MAIN];

        /* set initial remote address. This triggers connecting with that
         * session. So we only do that if the TM_ACTIVE session is not
         * established */
        if (i == TM_INIT && ks->state == S_INITIAL && multi->reno_stat
            && !link_socket_actual_defined(&ks->remote_addr)
            && link_socket_actual_defined(&to_link_socket_info->lsa->actual))
        {
            ks->remote_addr = to_link_socket_info->lsa->actual;
        }
        if ((TM_LAME < i) && (i < TM_SIZE))
        {
            continue;
        }

        dmsg(D_TLS_DEBUG,
             "TLS: tls_multi_process: i=%d state=%s, mysid=%s, stored-sid=%s, stored-ip=%s", i,
             state_name(ks->state), session_id_print(&session->session_id, &gc),
             session_id_print(&ks->session_id_remote, &gc),
             print_link_socket_actual(&ks->remote_addr, &gc));

        if ((ks->state >= S_INITIAL || ks->state == S_ERROR_PRE)
            && link_socket_actual_defined(&ks->remote_addr))
        {
            struct link_socket_actual *tla = NULL;

            update_time();

            if (tls_process(multi, session, to_link, &tla, to_link_socket_info, wakeup))
            {
                active = TLSMP_ACTIVE;
            }

            /*
             * If tls_process produced an outgoing packet,
             * return the link_socket_actual object (which
             * contains the outgoing address).
             */
            if (tla)
            {
                multi->to_link_addr = *tla;
                *to_link_addr = &multi->to_link_addr;
            }

            /*
             * If tls_process hits an error:
             * (1) If the session has an unexpired lame duck key, preserve it.
             * (2) Reinitialize the session.
             * (3) Increment soft error count
             */
            if (ks->state == S_ERROR)
            {
                ++multi->n_soft_errors;

                if (i == TM_MAIN)
                {
                    error = true;
                }

                check_session_buf_not_used(to_link, session);
                reset_session(multi, session);
            }
        }

        /* If we have successfully authenticated and are still waiting for the authentication to finish
         * move the state machine for the multi context forward */

        if (multi->multi_state >= CAS_CONNECT_DONE)
        {
            /* Only generate keys for the TM_ACTIVE session. We defer generating
             * keys for TM_INITIAL until we actually trust it.
             * For TM_LAME_DUCK it makes no sense to generate new keys. */

            if (ks->state == S_ACTIVE && ks->authenticated == KS_AUTH_TRUE)
            {
                /* Session is now fully authenticated.
                 * tls_session_generate_data_channel_keys will move ks->state
                 * from S_ACTIVE to S_GENERATED_KEYS */

                if (!tls_session_generate_data_channel_keys(multi, session, ks))
                {
                    msg(D_TLS_ERRORS, "TLS Error: generate_key_expansion failed");
                    ks->authenticated = KS_AUTH_FALSE;
                    key_state_ssl_shutdown(ks->ks_ssl);
                    ks->state = S_ERROR_PRE;
                }

                /* Update auth token on the client if needed on renegotiation
                 * (key id != 0) */

                if (i == TM_MAIN)
                {
                    resend_auth_token_renegotiation(multi);
                }
            }
        }

        if (i == TM_MAIN && ks->state == S_GENERATED_KEYS && ks->authenticated == KS_AUTH_TRUE && multi->gens_stat)
        {
            tls_session_generate_data_keys_helper(multi, session, ks);
        }
    }

    enum tls_auth_status tas = tls_authentication_status(multi);

    if (multi->multi_state == CAS_WAITING_AUTH && tas == TLS_AUTHENTICATION_SUCCEEDED)
    {
        multi->multi_state = CAS_PENDING;
    }

    /*
     * If untrusted session achieves TLS authentication,
     * move it to active session, usurping any prior session.
     *
     * A semi-trusted session is one in which the certificate authentication
     * succeeded (if cert verification is enabled) but the username/password
     * verification failed.  A semi-trusted session can forward data on the
     * TLS control channel but not on the tunnel channel.
     */
    if (TLS_AUTHENTICATED(multi, &multi->session[TM_INIT].key[KS_MAIN]))
    {
        struct tls_session *sn = &multi->session[TM_INIT];
        struct key_state *ks = &sn->key[KS_MAIN];
        struct key_state *kx, *kl;
        int indx = 0;
        int idno = ((TM_MAIN + 0) + multi->lame_mods[indx]);
        int mods = ((multi->lame_mods[indx] + 1) % 3);
        int KEYS_INDX = TM_MAIN, LAME_INDX = TM_LAME;

        if (sn->verified && !multi->verified)
        {
            multi->verified = sn->verified;
            multi->common_name = sn->common_name;
            multi->verify_maxlevel = sn->verify_maxlevel;
        }

        move_session(multi, LAME_INDX, KEYS_INDX, true);
        move_session(multi, KEYS_INDX, TM_INIT, true);
        tas = tls_authentication_status(multi);
        msg(D_TLS_DEBUG_LOW,
            "TLS: tls_multi_process: initial untrusted "
            "session promoted to %strusted",
            tas == TLS_AUTHENTICATION_SUCCEEDED ? "" : "semi-");

        /* k0 */

        ks = &multi->session[KEYS_INDX].key[KS_MAIN];
        kl = &multi->session[LAME_INDX].key[KS_MAIN];

        ks->key_id = idno;
        kl->keys_lame = true;
        multi->lame_mods[indx] = mods;

        /* k1 */

        indx = 1;
        idno = ((TM_SERV + 1) + multi->lame_mods[indx]);
        mods = ((multi->lame_mods[indx] + 1) % 3);
        KEYS_INDX = TM_SERV; LAME_INDX = TM_BACK;

        move_session(multi, LAME_INDX, KEYS_INDX, true);

        kx = &multi->session[KEYS_INDX].key[KS_MAIN];
        kl = &multi->session[LAME_INDX].key[KS_MAIN];

        kx->key_id = idno;
        multi->lame_mods[indx] = mods;

        /* k2 */

        indx = 2;
        idno = multi->lame_mods[indx];
        mods = (multi->lame_mods[indx] ^ P_KEY_ID_MASK);
        KEYS_INDX = TM_NOOP; LAME_INDX = TM_NULL;

        move_session(multi, LAME_INDX, KEYS_INDX, true);

        kx = &multi->session[KEYS_INDX].key[KS_MAIN];
        kl = &multi->session[LAME_INDX].key[KS_MAIN];

        kx->key_id = idno;
        multi->lame_mods[indx] = mods;

        /* k3 */

        multi->gens_stat = true;
        multi->reno_stat = false;
        multi->reno_last = time(NULL);
    }

    /*
     * A hard error means that TM_ACTIVE hit an S_ERROR state and that no
     * other key state objects are S_ACTIVE or higher.
     */
    if (error)
    {
        for (int i = 0; i < KEY_SCAN_SIZE; ++i)
        {
            if (get_key_scan(multi, i)->state >= S_ACTIVE)
            {
                goto nohard;
            }
        }
        ++multi->n_hard_errors;
    }
nohard:

#ifdef ENABLE_DEBUG
    /* DEBUGGING -- flood peer with repeating connection attempts */
    {
        const int throw_level = GREMLIN_CONNECTION_FLOOD_LEVEL(multi->opt.gremlin);
        if (throw_level)
        {
            for (int i = 0; i < KEY_SCAN_SIZE; ++i)
            {
                if (get_key_scan(multi, i)->state >= throw_level)
                {
                    ++multi->n_hard_errors;
                    ++multi->n_soft_errors;
                }
            }
        }
    }
#endif

    gc_free(&gc);

    return (tas == TLS_AUTHENTICATION_FAILED) ? TLSMP_KILL : active;
}

/**
 * We have not found a matching key to decrypt data channel packet,
 * try to generate a sensible error message and print it
 */
static void
print_key_id_not_found_reason(struct tls_multi *multi, const struct link_socket_actual *from,
                              int key_id)
{
    struct gc_arena gc = gc_new();
    const char *source = print_link_socket_actual(from, &gc);


    for (int i = 0; i < KEY_SCAN_SIZE; ++i)
    {
        struct key_state *ks = get_key_scan(multi, i);
        if (ks->key_id != key_id)
        {
            continue;
        }

        /* Our key state has been progressed far enough to be part of a valid
         * session but has not generated keys. */
        if (ks->state >= S_INITIAL && ks->state < S_GENERATED_KEYS)
        {
            msg(D_MULTI_DROPPED, "Key %s [%d] not initialized (yet), dropping packet.", source,
                key_id);
            gc_free(&gc);
            return;
        }
        if (ks->state >= S_ACTIVE && ks->authenticated != KS_AUTH_TRUE)
        {
            msg(D_MULTI_DROPPED, "Key %s [%d] not authorized%s, dropping packet.", source, key_id,
                (ks->authenticated == KS_AUTH_DEFERRED) ? " (deferred)" : "");
            gc_free(&gc);
            return;
        }
    }

    msg(D_TLS_ERRORS,
        "TLS Error: local/remote TLS keys are out of sync: %s "
        "(received key id: %d, known key ids: %s)",
        source, key_id, print_key_id(multi, &gc));
    gc_free(&gc);
}

/**
 * Check the keyid of the an incoming data channel packet and
 * return the matching crypto parameters in \c opt if found.
 * Also move the \c buf to the start of the encrypted data, skipping
 * the opcode and peer id header and setting also set \c ad_start for
 * AEAD ciphers to the start of the authenticated data.
 */
static inline void
handle_data_channel_packet(struct tls_multi *multi, const struct link_socket_actual *from,
                           struct buffer *buf, struct crypto_options **opt, bool floated,
                           const uint8_t **ad_start)
{
    struct gc_arena gc = gc_new();

    uint8_t c = *BPTR(buf);
    int op = c >> P_OPCODE_SHIFT;
    int key_id = c & P_KEY_ID_MASK;

    for (int i = 0; i < KEY_SCAN_SIZE; ++i)
    {
        struct key_state *ks = get_key_scan(multi, i);

        /*
         * This is the basic test of TLS state compatibility between a local OpenVPN
         * instance and its remote peer.
         *
         * If the test fails, it tells us that we are getting a packet from a source
         * which claims reference to a prior negotiated TLS session, but the local
         * OpenVPN instance has no memory of such a negotiation.
         *
         * It almost always occurs on UDP sessions when the passive side of the
         * connection is restarted without the active side restarting as well (the
         * passive side is the server which only listens for the connections, the
         * active side is the client which initiates connections).
         */
        if (ks->state >= S_GENERATED_KEYS && ks->key_id == key_id
            && ks->authenticated == KS_AUTH_TRUE
            && (floated || link_socket_actual_match(from, &ks->remote_addr)))
        {
            ASSERT(ks->crypto_options.key_ctx_bi.initialized);
            /* return appropriate data channel decrypt key in opt */
            *opt = &ks->crypto_options;
            if ((op == P_DATA_V2) || (op == P_KEYS_V1))
            {
                *ad_start = BPTR(buf);
            }
            ASSERT(buf_advance(buf, 1));
            if (op == P_DATA_V1)
            {
                *ad_start = BPTR(buf);
            }
            else if ((op == P_DATA_V2) || (op == P_KEYS_V1))
            {
                if (buf->len < 4)
                {
                    msg(D_TLS_ERRORS,
                        "Protocol error: received P_DATA_V2 from %s but length is < 4",
                        print_link_socket_actual(from, &gc));
                    ++multi->n_soft_errors;
                    goto done;
                }
                ASSERT(buf_advance(buf, 3));
            }

            ++ks->n_packets;
            ks->n_bytes += buf->len;
            dmsg(D_TLS_KEYSELECT, "TLS: tls_pre_decrypt, key_id=%d, IP=%s", key_id,
                 print_link_socket_actual(from, &gc));
            gc_free(&gc);
            return;
        }
    }

    print_key_id_not_found_reason(multi, from, key_id);

done:
    gc_free(&gc);
    tls_clear_error();
    buf->len = 0;
    *opt = NULL;
}

/*
 *
 * When we are in TLS mode, this is the first routine which sees
 * an incoming packet.
 *
 * If it's a data packet, we set opt so that our caller can
 * decrypt it.  We also give our caller the appropriate decryption key.
 *
 * If it's a control packet, we authenticate it and process it,
 * possibly creating a new tls_session if it represents the
 * first packet of a new session.  For control packets, we will
 * also zero the size of *buf so that our caller ignores the
 * packet on our return.
 *
 * Note that openvpn only allows one active session at a time,
 * so a new session (once authenticated) will always usurp
 * an old session.
 *
 * Return true if input was an authenticated control channel
 * packet.
 *
 * If we are running in TLS thread mode, all public routines
 * below this point must be called with the L_TLS lock held.
 */

bool
tls_pre_decrypt(struct tls_multi *multi, const struct link_socket_actual *from, struct buffer *buf,
                struct crypto_options **opt, bool floated, const uint8_t **ad_start)
{
    if (buf->len <= 0)
    {
        buf->len = 0;
        *opt = NULL;
        return false;
    }

    struct gc_arena gc = gc_new();
    bool ret = false;

    /* get opcode  */
    uint8_t pkt_firstbyte = *BPTR(buf);
    int op = pkt_firstbyte >> P_OPCODE_SHIFT;

    if ((op == P_DATA_V1) || (op == P_DATA_V2) || (op == P_KEYS_V1))
    {
        handle_data_channel_packet(multi, from, buf, opt, floated, ad_start);
        return false;
    }

    /* get key_id */
    int key_id = pkt_firstbyte & P_KEY_ID_MASK;

    /* control channel packet */
    bool do_burst = false;
    bool new_link = false;
    struct session_id sid; /* remote session ID */

    /* verify legal opcode */
    if (op < P_FIRST_OPCODE || op > P_LAST_OPCODE)
    {
        if (op == P_CONTROL_HARD_RESET_CLIENT_V1 || op == P_CONTROL_HARD_RESET_SERVER_V1)
        {
            msg(D_TLS_ERRORS, "Peer tried unsupported key-method 1");
        }
        msg(D_TLS_ERRORS, "TLS Error: unknown opcode received from %s op=%d",
            print_link_socket_actual(from, &gc), op);
        goto error;
    }

    /* hard reset ? */
    if (is_hard_reset_method2(op))
    {
        /* verify client -> server or server -> client connection */
        if (((op == P_CONTROL_HARD_RESET_CLIENT_V2 || op == P_CONTROL_HARD_RESET_CLIENT_V3)
             && !multi->opt.server)
            || ((op == P_CONTROL_HARD_RESET_SERVER_V2) && multi->opt.server))
        {
            msg(D_TLS_ERRORS,
                "TLS Error: client->client or server->server connection attempted from %s",
                print_link_socket_actual(from, &gc));
            goto error;
        }
    }

    /*
     * Authenticate Packet
     */
    dmsg(D_TLS_DEBUG, "TLS: control channel, op=%s, IP=%s", packet_opcode_name(op),
         print_link_socket_actual(from, &gc));

    /* get remote session-id */
    {
        struct buffer tmp = *buf;
        buf_advance(&tmp, 1);
        if (!session_id_read(&sid, &tmp) || !session_id_defined(&sid))
        {
            msg(D_TLS_ERRORS, "TLS Error: session-id not found in packet from %s",
                print_link_socket_actual(from, &gc));
            goto error;
        }
    }

    int i;
    /* use session ID to match up packet with appropriate tls_session object */
    for (i = 0; i < TM_SIZE; ++i)
    {
        struct tls_session *session = &multi->session[i];
        struct key_state *ks = &session->key[KS_MAIN];

        dmsg(
            D_TLS_DEBUG,
            "TLS: initial packet test, i=%d state=%s, mysid=%s, rec-sid=%s, rec-ip=%s, stored-sid=%s, stored-ip=%s",
            i, state_name(ks->state), session_id_print(&session->session_id, &gc),
            session_id_print(&sid, &gc), print_link_socket_actual(from, &gc),
            session_id_print(&ks->session_id_remote, &gc),
            print_link_socket_actual(&ks->remote_addr, &gc));

        if (session_id_equal(&ks->session_id_remote, &sid))
        /* found a match */
        {
            dmsg(D_TLS_DEBUG, "TLS: found match, session[%d], sid=%s", i,
                 session_id_print(&sid, &gc));
            break;
        }
    }

    /*
     * Hard reset and session id does not match any session in
     * multi->session: Possible initial packet. New sessions always start
     * as TM_INITIAL
     */
    if (i == TM_SIZE && is_hard_reset_method2(op))
    {
        /*
         * No match with existing sessions,
         * probably a new session.
         */
        struct tls_session *session = &multi->session[TM_INIT];
        struct tls_wrap_ctx *wrap = tls_session_get_tls_wrap(multi, session);

        /*
         * If --single-session, don't allow any hard-reset connection request
         * unless it is the first packet of the session.
         */
        if (multi->opt.single_session && multi->n_sessions)
        {
            msg(D_TLS_ERRORS,
                "TLS Error: Cannot accept new session request from %s due "
                "to session context expire or --single-session",
                print_link_socket_actual(from, &gc));
            goto error;
        }

        if (!read_control_auth(multi, buf, wrap, from, session->opt, true))
        {
            goto error;
        }

#ifdef ENABLE_MANAGEMENT
        if (management)
        {
            management_set_state(management, OPENVPN_STATE_AUTH, NULL, NULL, NULL, NULL, NULL);
        }
#endif

        /*
         * New session-initiating control packet is authenticated at this point,
         * assuming that the --tls-auth command line option was used.
         *
         * Without --tls-auth, we leave authentication entirely up to TLS.
         */
        msg(D_TLS_DEBUG_LOW, "TLS: Initial packet from %s, sid=%s",
            print_link_socket_actual(from, &gc), session_id_print(&sid, &gc));

        do_burst = true;
        new_link = true;
        i = TM_INIT;

        //session->untrusted_addr = *from;
    }
    else
    {
        /*
         * Packet must belong to an existing session.
         */
        if (i >= TM_SIZE)
        {
            msg(D_TLS_ERRORS, "TLS Error: Unroutable control packet received from %s (si=%d op=%s)",
                print_link_socket_actual(from, &gc), i, packet_opcode_name(op));
            goto error;
        }

        struct tls_session *session = &multi->session[i];
        struct key_state *ks = &session->key[KS_MAIN];
        struct tls_wrap_ctx *wrap = tls_session_get_tls_wrap(multi, session);

        /*
         * Verify remote IP address
         */
        if (!new_link && !link_socket_actual_match(&ks->remote_addr, from))
        {
            msg(D_TLS_ERRORS, "TLS Error: Received control packet from unexpected IP addr: %s",
                print_link_socket_actual(from, &gc));
            goto error;
        }

        /*
         * Remote is requesting a key renegotiation.  We only allow renegotiation
         * when the previous session is fully established to avoid weird corner
         * cases.
         */
        if (op == P_CONTROL_SOFT_RESET_V1 && ks->state >= S_GENERATED_KEYS)
        {
            if (!read_control_auth(multi, buf, wrap, from, session->opt, false))
            {
                goto error;
            }

            key_state_soft_reset(multi, true, "P_CONTROL_SOFT_RESET_V1");

            dmsg(D_TLS_DEBUG, "TLS: received P_CONTROL_SOFT_RESET_V1 s=%d sid=%s", i,
                 session_id_print(&sid, &gc));
        }
        else
        {
            bool initial_packet = false;

            if (ks->state == S_PRE_START_SKIP)
            {
                /* When we are coming from the session_skip_to_pre_start
                 * method, we allow this initial packet to setup the
                 * tls-crypt-v2 peer specific key */
                initial_packet = true;
                ks->state = S_PRE_START;
            }
            /*
             * Remote responding to our key renegotiation request?
             */
            if (op == P_CONTROL_SOFT_RESET_V1)
            {
                do_burst = true;
            }

            if (!read_control_auth(multi, buf, wrap, from, session->opt, initial_packet))
            {
                /* if an initial packet in read_control_auth, we rather
                 * error out than anything else */
                if (initial_packet)
                {
                    multi->n_hard_errors++;
                }
                goto error;
            }

            dmsg(D_TLS_DEBUG, "TLS: received control channel packet s#=%d sid=%s", i,
                 session_id_print(&sid, &gc));
        }
    }

    /*
     * We have an authenticated control channel packet (if --tls-auth/tls-crypt
     * or tls-crypt-v2 was set).
     * Now pass to our reliability layer which deals with
     * packet acknowledgements, retransmits, sequencing, etc.
     */
    struct tls_session *session = &multi->session[i];
    struct key_state *ks = &session->key[KS_MAIN];

    /* Make sure we were initialized and that we're not in an error state */
    ASSERT(ks->state != S_UNDEF);
    ASSERT(ks->state != S_ERROR);
    ASSERT(session_id_defined(&session->session_id));

    /* Let our caller know we processed a control channel packet */
    ret = true;

    /*
     * Set our remote address and remote session_id
     */
    if (new_link)
    {
        ks->session_id_remote = sid;
        key_state_soft_reset(multi, true, "tls_pre_decrypt");
    }
    else if (!link_socket_actual_match(&ks->remote_addr, from))
    {
        msg(D_TLS_ERRORS, "TLS Error: Existing session control channel packet from unknown IP address: %s",
            print_link_socket_actual(from, &gc));
        goto error;
    }
    else if (ks->key_id != key_id)
    {
        msg(D_TLS_ERRORS, "TLS ERROR: local/remote key IDs out of sync (%d/%d) sid=[%s] ID: %s", key_id,
            ks->key_id, session_id_print(&sid, &gc), print_key_id(multi, &gc));
        goto error;
    }

    /*
     * Should we do a retransmit of all unacknowledged packets in
     * the send buffer?  This improves the start-up efficiency of the
     * initial key negotiation after the 2nd peer comes online.
     */
    if (do_burst && !session->burst)
    {
        session->burst = true;
    }

    packet_id_type id;

    /* Extract the packet ID from the packet */
    if (buf_ack_read_packet_id(buf, &id))
    {
        int num = (id - PAID_INDX);
        int idx = (((num >> 4) & 0xf) - 1);
        int len = (((num >> 0) & 0xf) - 0);
        if ((0 <= idx) && (idx <= KEYS_SIZE))
        {
            /* Save incoming ciphertext packet to reliable buffer */
            idx = find_next_indx(multi->read_code, idx);
            int *opc = &multi->read_code[idx];
            struct buffer *inp = &multi->read_buff[idx];
            *opc = op;
            buf_init(inp, BUFF_OFFS);
            if (!buf_copy(inp, buf))
            {
                msg(D_MULTI_DROPPED, "Incoming control channel packet too big, dropping.");
                goto error;
            }
            multi->part_leng[idx] = len;
        }
    }

    /* Remember that we received a valid control channel packet */
    *ks->peer_last_packet = now;

done:
    buf->len = 0;
    *opt = NULL;
    gc_free(&gc);
    return ret;

error:
    ++multi->n_soft_errors;
    tls_clear_error();
    goto done;
}


/* Choose the key with which to encrypt a data packet */
void
tls_pre_encrypt(struct tls_multi *multi, struct buffer *buf, struct crypto_options **opt)
{
    multi->save_ks = NULL;
    if (buf->len <= 0)
    {
        buf->len = 0;
        *opt = NULL;
        return;
    }

    struct key_state *ks_select = tls_select_encryption_key(multi);

    if (ks_select)
    {
        *opt = &ks_select->crypto_options;
        multi->save_ks = ks_select;
        dmsg(D_TLS_KEYSELECT, "TLS: tls_pre_encrypt: key_id=%d", ks_select->key_id);
        return;
    }
    else
    {
        struct gc_arena gc = gc_new();
        dmsg(D_TLS_KEYSELECT, "TLS Warning: no data channel send key available: %s",
             print_key_id(multi, &gc));
        gc_free(&gc);

        *opt = NULL;
        buf->len = 0;
    }
}

void
tls_prepend_opcode_v1(const struct tls_multi *multi, struct buffer *buf)
{
    struct key_state *ks = multi->save_ks;

    msg(D_TLS_DEBUG, __func__);

    ASSERT(ks);
    ASSERT(ks->key_id <= P_KEY_ID_MASK);

    uint8_t op = (P_DATA_V1 << P_OPCODE_SHIFT) | (uint8_t)ks->key_id;
    ASSERT(buf_write_prepend(buf, &op, 1));
}

void
tls_prepend_opcode_v2(const struct tls_multi *multi, struct buffer *buf)
{
    struct key_state *ks = multi->save_ks;
    uint32_t peer;

    msg(D_TLS_DEBUG, __func__);

    ASSERT(ks);

    peer = htonl(((P_DATA_V2 << P_OPCODE_SHIFT) | ks->key_id) << 24 | (multi->peer_id & 0xFFFFFF));
    ASSERT(buf_write_prepend(buf, &peer, 4));
}

void
tls_prepend_opcode_k1(const struct tls_multi *multi, struct buffer *buf)
{
    struct key_state *ks = multi->save_ks;
    uint32_t peer;

    msg(D_TLS_DEBUG, __func__);

    ASSERT(ks);

    peer = htonl(((P_KEYS_V1 << P_OPCODE_SHIFT) | ks->key_id) << 24 | (multi->peer_id & 0xFFFFFF));
    ASSERT(buf_write_prepend(buf, &peer, 4));
}

void
tls_post_encrypt(struct tls_multi *multi, struct buffer *buf)
{
    struct key_state *ks = multi->save_ks;
    multi->save_ks = NULL;

    if (buf->len > 0)
    {
        ASSERT(ks);

        ++ks->n_packets;
        ks->n_bytes += buf->len;
    }
}

/*
 * Send a payload over the TLS control channel.
 * Called externally.
 */

bool
tls_send_payload(struct key_state *ks, const uint8_t *data, size_t size)
{
    bool ret = false;

    tls_clear_error();

    ASSERT(ks);

    if (ks->state >= S_ACTIVE)
    {
        ASSERT(size <= INT_MAX);
        if (key_state_write_plaintext_const(ks->ks_ssl, data, (int)size) == 1)
        {
            ret = true;
        }
    }

    tls_clear_error();

    return ret;
}

bool
tls_rec_payload(struct tls_multi *multi, struct buffer *buf)
{
    tls_clear_error();

    ASSERT(multi);

    for (int i = 0; i < KEY_SCAN_SIZE; ++i)
    {
        struct key_state *ks = get_key_scan(multi, i);

        if (ks->state >= S_ACTIVE && BLEN(&ks->plaintext_read_buf))
        {
            buf_copy(buf, &ks->plaintext_read_buf);
            ks->plaintext_read_buf.len = 0;
            return true;
        }
    }

    tls_clear_error();

    return false;
}

void
tls_update_remote_addr(struct tls_multi *multi, const struct link_socket_actual *addr)
{
    struct gc_arena gc = gc_new();
    for (int i = 0; i < TM_SIZE; ++i)
    {
        struct tls_session *session = &multi->session[i];

        for (int j = 0; j < KS_SIZE; ++j)
        {
            struct key_state *ks = &session->key[j];

            if (!link_socket_actual_defined(&ks->remote_addr)
                || link_socket_actual_match(addr, &ks->remote_addr))
            {
                continue;
            }

            dmsg(D_TLS_KEYSELECT, "TLS: tls_update_remote_addr from IP=%s to IP=%s",
                 print_link_socket_actual(&ks->remote_addr, &gc),
                 print_link_socket_actual(addr, &gc));

            ks->remote_addr = *addr;
        }
    }
    gc_free(&gc);
}

void
show_available_tls_ciphers(const char *cipher_list, const char *cipher_list_tls13,
                           const char *tls_cert_profile)
{
    printf("Available TLS Ciphers, listed in order of preference:\n");

    if (tls_version_max() >= TLS_VER_1_3)
    {
        printf("\nFor TLS 1.3 and newer (--tls-ciphersuites):\n\n");
        show_available_tls_ciphers_list(cipher_list_tls13, tls_cert_profile, true);
    }

    printf("\nFor TLS 1.2 and older (--tls-cipher):\n\n");
    show_available_tls_ciphers_list(cipher_list, tls_cert_profile, false);

    printf("\n"
           "Be aware that that whether a cipher suite in this list can actually work\n"
           "depends on the specific setup of both peers. See the man page entries of\n"
           "--tls-cipher and --show-tls for more details.\n\n");
}

/*
 * Dump a human-readable rendition of an openvpn packet
 * into a garbage collectable string which is returned.
 */
const char *
protocol_dump(struct buffer *buffer, unsigned int flags, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);
    struct buffer buf = *buffer;

    uint8_t c;
    int op;
    int key_id;

    int tls_auth_hmac_size = (flags & PD_TLS_AUTH_HMAC_SIZE_MASK);

    if (buf.len <= 0)
    {
        buf_printf(&out, "DATA UNDEF len=%d", buf.len);
        goto done;
    }

    if (!(flags & PD_TLS))
    {
        goto print_data;
    }

    /*
     * Initial byte (opcode)
     */
    if (!buf_read(&buf, &c, sizeof(c)))
    {
        goto done;
    }
    op = (c >> P_OPCODE_SHIFT);
    key_id = c & P_KEY_ID_MASK;
    buf_printf(&out, "%s kid=%d", packet_opcode_name(op), key_id);

    if ((op == P_DATA_V1) || (op == P_DATA_V2))
    {
        goto print_data;
    }

    /*
     * Session ID
     */
    {
        struct session_id sid;

        if (!session_id_read(&sid, &buf))
        {
            goto done;
        }
        if (flags & PD_VERBOSE)
        {
            buf_printf(&out, " sid=%s", session_id_print(&sid, gc));
        }
    }

    /*
     * tls-auth hmac + packet_id
     */
    if (tls_auth_hmac_size)
    {
        struct packet_id_net pin;
        uint8_t tls_auth_hmac[MAX_HMAC_KEY_LENGTH];

        ASSERT(tls_auth_hmac_size <= MAX_HMAC_KEY_LENGTH);

        if (!buf_read(&buf, tls_auth_hmac, tls_auth_hmac_size))
        {
            goto done;
        }
        if (flags & PD_VERBOSE)
        {
            buf_printf(&out, " tls_hmac=%s", format_hex(tls_auth_hmac, tls_auth_hmac_size, 0, gc));
        }

        if (!packet_id_read(&pin, &buf, true))
        {
            goto done;
        }
        buf_printf(&out, " pid=%s", packet_id_net_print(&pin, (flags & PD_VERBOSE), gc));
    }
    /*
     * packet_id + tls-crypt hmac
     */
    if (flags & PD_TLS_CRYPT)
    {
        struct packet_id_net pin;
        uint8_t tls_crypt_hmac[TLS_CRYPT_TAG_SIZE];

        if (!packet_id_read(&pin, &buf, true))
        {
            goto done;
        }
        buf_printf(&out, " pid=%s", packet_id_net_print(&pin, (flags & PD_VERBOSE), gc));
        if (!buf_read(&buf, tls_crypt_hmac, TLS_CRYPT_TAG_SIZE))
        {
            goto done;
        }
        if (flags & PD_VERBOSE)
        {
            buf_printf(&out, " tls_crypt_hmac=%s",
                       format_hex(tls_crypt_hmac, TLS_CRYPT_TAG_SIZE, 0, gc));
        }
        /*
         * Remainder is encrypted and optional wKc
         */
        goto done;
    }

    /*
     * Packet ID
     */
    {
        packet_id_type l;
        if (!buf_read(&buf, &l, sizeof(l)))
        {
            goto done;
        }
        l = ntohpid(l);
        buf_printf(&out, " pid=" packet_id_format, (packet_id_print_type)l);
    }

print_data:
    if (flags & PD_SHOW_DATA)
    {
        buf_printf(&out, " DATA %s", format_hex(BPTR(&buf), BLEN(&buf), 80, gc));
    }
    else
    {
        buf_printf(&out, " DATA len=%d", buf.len);
    }

done:
    return BSTR(&out);
}
