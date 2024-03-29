/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
 *  Copyright (C) 2008-2024 David Sommerseth <dazo@eurephia.org>
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
 * @file Control Channel SSL/Data channel negotiation Module
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
#include "perf.h"
#include "status.h"
#include "gremlin.h"
#include "pkcs11.h"
#include "route.h"
#include "tls_crypt.h"

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

#define INCR_SENT       ++tls_packets_sent
#define INCR_GENERATED  ++tls_packets_generated
#define INCR_SUCCESS    ++tls_handshake_success
#define INCR_ERROR      ++tls_handshake_error

void
show_tls_performance_stats(void)
{
    msg(D_TLS_DEBUG_LOW, "TLS Handshakes, success=%f%% (good=%d, bad=%d), retransmits=%f%%",
        (double) tls_handshake_success / (tls_handshake_success + tls_handshake_error) * 100.0,
        tls_handshake_success, tls_handshake_error,
        (double) (tls_packets_sent - tls_packets_generated) / tls_packets_generated * 100.0);
}
#else  /* ifdef MEASURE_TLS_HANDSHAKE_STATS */

#define INCR_SENT
#define INCR_GENERATED
#define INCR_SUCCESS
#define INCR_ERROR

#endif /* ifdef MEASURE_TLS_HANDSHAKE_STATS */

/**
 * Update the implicit IV for a key_ctx_bi based on TLS session ids and cipher
 * used.
 *
 * Note that the implicit IV is based on the HMAC key, but only in AEAD modes
 * where the HMAC key is not used for an actual HMAC.
 *
 * @param ctx                   Encrypt/decrypt key context
 * @param key                   HMAC key, used to calculate implicit IV
 * @param key_len               HMAC key length
 */
static void
key_ctx_update_implicit_iv(struct key_ctx *ctx, uint8_t *key, size_t key_len);


/**
 * Limit the reneg_bytes value when using a small-block (<128 bytes) cipher.
 *
 * @param cipher        The current cipher (may be NULL).
 * @param reneg_bytes   Pointer to the current reneg_bytes, updated if needed.
 *                      May *not* be NULL.
 */
static void
tls_limit_reneg_bytes(const char *ciphername, int *reneg_bytes)
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
    overhead += max_int(tls_crypt_buf_overhead(),
                        packet_id_size(true) + OPENVPN_MAX_HMAC_SIZE);

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

/**
 * calculate the maximum overhead that control channel frames have
 * This includes header, op code and everything apart from the
 * payload itself. This method is a bit pessimistic and might give higher
 * overhead than we actually have */
static int
calc_control_channel_frame_overhead(const struct tls_session *session)
{
    const struct key_state *ks = &session->key[KS_PRIMARY];
    int overhead = 0;

    /* opcode */
    overhead += 1;

    /* our own session id */
    overhead += SID_SIZE;

    /* ACK array and remote SESSION ID (part of the ACK array) */
    int ackstosend = reliable_ack_outstanding(ks->rec_ack) + ks->lru_acks->len;
    overhead += ACK_SIZE(min_int(ackstosend, CONTROL_SEND_ACK_MAX));

    /* Message packet id */
    overhead += sizeof(packet_id_type);

    if (session->tls_wrap.mode == TLS_WRAP_CRYPT)
    {
        overhead += tls_crypt_buf_overhead();
    }
    else if (session->tls_wrap.mode == TLS_WRAP_AUTH)
    {
        overhead += hmac_ctx_size(session->tls_wrap.opt.key_ctx_bi.encrypt.hmac);
        overhead += packet_id_size(true);
    }

    /* Add the typical UDP overhead for an IPv6 UDP packet. TCP+IPv6 has a
     * larger overhead but the risk of a TCP connection getting dropped because
     * we try to send a too large packet is basically zero */
    overhead += datagram_overhead(session->untrusted_addr.dest.addr.sa.sa_family,
                                  PROTO_UDP);

    return overhead;
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
    if (!strlen(passbuf.password))
    {
        get_user_pass(&passbuf, auth_file, UP_TYPE_PRIVATE_KEY, GET_USER_PASS_MANAGEMENT|GET_USER_PASS_PASSWORD_ONLY);
    }
}

int
pem_password_callback(char *buf, int size, int rwflag, void *u)
{
    if (buf)
    {
        /* prompt for password even if --askpass wasn't specified */
        pem_password_setup(NULL);
        strncpynt(buf, passbuf.password, size);
        purge_user_pass(&passbuf, false);

        return strlen(buf);
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
enable_auth_user_pass()
{
    auth_user_pass_enabled = true;
}

void
auth_user_pass_setup(const char *auth_file, bool is_inline,
                     const struct static_challenge_info *sci)
{
    unsigned int flags = GET_USER_PASS_MANAGEMENT;

    if (is_inline)
    {
        flags |= GET_USER_PASS_INLINE_CREDS;
    }

    if (!auth_user_pass.defined && !auth_token.defined)
    {
#ifdef ENABLE_MANAGEMENT
        if (auth_challenge) /* dynamic challenge/response */
        {
            flags |= GET_USER_PASS_DYNAMIC_CHALLENGE;
            get_user_pass_cr(&auth_user_pass,
                             auth_file,
                             UP_TYPE_AUTH,
                             flags,
                             auth_challenge);
        }
        else if (sci) /* static challenge response */
        {
            flags |= GET_USER_PASS_STATIC_CHALLENGE;
            if (sci->flags & SC_ECHO)
            {
                flags |= GET_USER_PASS_STATIC_CHALLENGE_ECHO;
            }
            get_user_pass_cr(&auth_user_pass,
                             auth_file,
                             UP_TYPE_AUTH,
                             flags,
                             sci->challenge_text);
        }
        else
#endif /* ifdef ENABLE_MANAGEMENT */
        get_user_pass(&auth_user_pass, auth_file, UP_TYPE_AUTH, flags);
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
 * @param ssl_ctx       The TLS context to use when reloading the CRL
 * @param crl_file      The file name to load the CRL from, or
 *                      "[[INLINE]]" in the case of inline files.
 * @param crl_inline    A string containing the CRL
 */
static void
tls_ctx_reload_crl(struct tls_root_ctx *ssl_ctx, const char *crl_file,
                   bool crl_file_inline)
{
    /* if something goes wrong with stat(), we'll store 0 as mtime */
    platform_stat_t crl_stat = {0};

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
            tls_ctx_load_dh_params(new_ctx, options->dh_file,
                                   options->dh_file_inline);
        }
    }
    else                        /* if client */
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
        if (0 != tls_ctx_load_pkcs12(new_ctx, options->pkcs12_file,
                                     options->pkcs12_file_inline, !options->ca_file))
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
#ifdef ENABLE_CRYPTOAPI
    else if (options->cryptoapi_cert)
    {
        tls_ctx_load_cryptoapi(new_ctx, options->cryptoapi_cert);
    }
#endif
#ifdef ENABLE_MANAGEMENT
    else if (options->management_flags & MF_EXTERNAL_CERT)
    {
        char *cert = management_query_cert(management,
                                           options->management_certificate);
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
        if (0 != tls_ctx_load_priv_file(new_ctx, options->priv_key_file,
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
        tls_ctx_load_ca(new_ctx, options->ca_file, options->ca_file_inline,
                        options->ca_path, options->tls_server);
    }

    /* Load extra certificates that are part of our own certificate
     * chain but shouldn't be included in the verify chain */
    if (options->extra_certs_file)
    {
        tls_ctx_load_extra_certs(new_ctx, options->extra_certs_file, options->extra_certs_file_inline);
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

#ifdef ENABLE_CRYPTO_MBEDTLS
    /* Personalise the random by mixing in the certificate */
    tls_ctx_personalise_random(new_ctx);
#endif

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
        case S_UNDEF:
            return "S_UNDEF";

        case S_INITIAL:
            return "S_INITIAL";

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

        case S_ERROR:
            return "S_ERROR";

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
        case TM_ACTIVE:
            return "TM_ACTIVE";

        case TM_INITIAL:
            return "TM_INITIAL";

        case TM_LAME_DUCK:
            return "TM_LAME_DUCK";

        default:
            return "TM_???";
    }
}

/*
 * For debugging.
 */
static const char *
print_key_id(struct tls_multi *multi, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);

    for (int i = 0; i < KEY_SCAN_SIZE; ++i)
    {
        struct key_state *ks = get_key_scan(multi, i);
        buf_printf(&out, " [key#%d state=%s auth=%s id=%d sid=%s]", i,
                   state_name(ks->state), ks_auth_name(ks->authenticated),
                   ks->key_id,
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
key_state_init(struct tls_session *session, struct key_state *ks)
{
    update_time();

    CLEAR(*ks);

    /*
     * Build TLS object that reads/writes ciphertext
     * to/from memory BIOs.
     */
    key_state_ssl_init(&ks->ks_ssl, &session->opt->ssl_ctx, session->opt->server,
                       session);

    /* Set control-channel initiation mode */
    ks->initial_opcode = session->initial_opcode;
    session->initial_opcode = P_CONTROL_SOFT_RESET_V1;
    ks->state = S_INITIAL;
    ks->key_id = session->key_id;

    /*
     * key_id increments to KEY_ID_MASK then recycles back to 1.
     * This way you know that if key_id is 0, it is the first key.
     */
    ++session->key_id;
    session->key_id &= P_KEY_ID_MASK;
    if (!session->key_id)
    {
        session->key_id = 1;
    }

    /* allocate key source material object */
    ALLOC_OBJ_CLEAR(ks->key_src, struct key_source2);

    /* allocate reliability objects */
    ALLOC_OBJ_CLEAR(ks->send_reliable, struct reliable);
    ALLOC_OBJ_CLEAR(ks->rec_reliable, struct reliable);
    ALLOC_OBJ_CLEAR(ks->rec_ack, struct reliable_ack);
    ALLOC_OBJ_CLEAR(ks->lru_acks, struct reliable_ack);

    /* allocate buffers */
    ks->plaintext_read_buf = alloc_buf(TLS_CHANNEL_BUF_SIZE);
    ks->plaintext_write_buf = alloc_buf(TLS_CHANNEL_BUF_SIZE);
    ks->ack_write_buf = alloc_buf(BUF_SIZE(&session->opt->frame));
    reliable_init(ks->send_reliable, BUF_SIZE(&session->opt->frame),
                  session->opt->frame.buf.headroom, TLS_RELIABLE_N_SEND_BUFFERS,
                  ks->key_id ? false : session->opt->xmit_hold);
    reliable_init(ks->rec_reliable, BUF_SIZE(&session->opt->frame),
                  session->opt->frame.buf.headroom, TLS_RELIABLE_N_REC_BUFFERS,
                  false);
    reliable_set_timeout(ks->send_reliable, session->opt->packet_timeout);

    /* init packet ID tracker */
    packet_id_init(&ks->crypto_options.packet_id,
                   session->opt->replay_window, session->opt->replay_time, "SSL",
                   ks->key_id);

    ks->crypto_options.pid_persist = NULL;

#ifdef ENABLE_MANAGEMENT
    ks->mda_key_id = session->opt->mda_context->mda_key_id_counter++;
#endif

    /*
     * Attempt CRL reload before TLS negotiation. Won't be performed if
     * the file was not modified since the last reload
     */
    if (session->opt->crl_file
        && !(session->opt->ssl_flags & SSLF_CRL_VERIFY_DIR))
    {
        tls_ctx_reload_crl(&session->opt->ssl_ctx,
                           session->opt->crl_file, session->opt->crl_file_inline);
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

    key_state_ssl_free(&ks->ks_ssl);

    free_key_ctx_bi(&ks->crypto_options.key_ctx_bi);
    free_buf(&ks->plaintext_read_buf);
    free_buf(&ks->plaintext_write_buf);
    free_buf(&ks->ack_write_buf);
    buffer_list_free(ks->paybuf);

    reliable_free(ks->send_reliable);
    reliable_free(ks->rec_reliable);

    free(ks->rec_ack);
    free(ks->lru_acks);
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
 * generating a random session ID, and initializing the \c KS_PRIMARY \c
 * key_state in the \c tls_session.key array.
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
    if (session->opt->server)
    {
        session->initial_opcode = P_CONTROL_HARD_RESET_SERVER_V2;
    }
    else
    {
        session->initial_opcode = session->opt->tls_crypt_v2 ?
                                  P_CONTROL_HARD_RESET_CLIENT_V3 : P_CONTROL_HARD_RESET_CLIENT_V2;
    }

    /* Initialize control channel authentication parameters */
    session->tls_wrap = session->opt->tls_wrap;
    session->tls_wrap.work = alloc_buf(BUF_SIZE(&session->opt->frame));

    /* initialize packet ID replay window for --tls-auth */
    packet_id_init(&session->tls_wrap.opt.packet_id,
                   session->opt->replay_window,
                   session->opt->replay_time,
                   "TLS_WRAP", session->key_id);

    /* If we are using tls-crypt-v2 we manipulate the packet id to be (ab)used
     * to indicate early protocol negotiation */
    if (session->opt->tls_crypt_v2)
    {
        session->tls_wrap.opt.packet_id.send.time = now;
        session->tls_wrap.opt.packet_id.send.id = EARLY_NEG_START;
    }

    /* load most recent packet-id to replay protect on --tls-auth */
    packet_id_persist_load_obj(session->tls_wrap.opt.pid_persist,
                               &session->tls_wrap.opt.packet_id);

    key_state_init(session, &session->key[KS_PRIMARY]);

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
    tls_wrap_free(&session->tls_wrap);
    tls_wrap_free(&session->tls_wrap_reneg);

    for (size_t i = 0; i < KS_SIZE; ++i)
    {
        /* we don't need clear=true for this call since
         * the structs are part of session and get cleared
         * as part of session */
        key_state_free(&session->key[i], false);
    }

    free(session->common_name);

    cert_hash_free(session->cert_hash_set);

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
        session_index_name(dest),
        session_index_name(src),
        reinit_src);
    ASSERT(src != dest);
    ASSERT(src >= 0 && src < TM_SIZE);
    ASSERT(dest >= 0 && dest < TM_SIZE);
    tls_session_free(&multi->session[dest], false);
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
    tls_session_free(session, false);
    tls_session_init(multi, session);
}

/*
 * Used to determine in how many seconds we should be
 * called again.
 */
static inline void
compute_earliest_wakeup(interval_t *earliest, interval_t seconds_from_now)
{
    if (seconds_from_now < *earliest)
    {
        *earliest = seconds_from_now;
    }
    if (*earliest < 0)
    {
        *earliest = 0;
    }
}

/*
 * Return true if "lame duck" or retiring key has expired and can
 * no longer be used.
 */
static inline bool
lame_duck_must_die(const struct tls_session *session, interval_t *wakeup)
{
    const struct key_state *lame = &session->key[KS_LAME_DUCK];
    if (lame->state >= S_INITIAL)
    {
        ASSERT(lame->must_die); /* a lame duck key must always have an expiration */
        if (now < lame->must_die)
        {
            compute_earliest_wakeup(wakeup, lame->must_die - now);
            return false;
        }
        else
        {
            return true;
        }
    }
    else if (lame->state == S_ERROR)
    {
        return true;
    }
    else
    {
        return false;
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

    return ret;
}

void
tls_multi_init_finalize(struct tls_multi *multi, int tls_mtu)
{
    tls_init_control_channel_frame_parameters(&multi->opt.frame, tls_mtu);
    /* initialize the active and untrusted sessions */

    tls_session_init(multi, &multi->session[TM_ACTIVE]);
    tls_session_init(multi, &multi->session[TM_INITIAL]);
}

/*
 * Initialize and finalize a standalone tls-auth verification object.
 */

struct tls_auth_standalone *
tls_auth_standalone_init(struct tls_options *tls_options,
                         struct gc_arena *gc)
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

    packet_id_init(&tas->tls_wrap.opt.packet_id, tls_options->replay_window,
                   tls_options->replay_time, "TAS", 0);

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
tls_multi_init_set_options(struct tls_multi *multi,
                           const char *local,
                           const char *remote)
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

    cert_hash_free(multi->locked_cert_hash_set);

    wipe_auth_token(multi);

    free(multi->remote_ciphername);

    for (int i = 0; i < TM_SIZE; ++i)
    {
        tls_session_free(&multi->session[i], false);
    }

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
key_source_print(const struct key_source *k,
                 const char *prefix)
{
    struct gc_arena gc = gc_new();

    VALGRIND_MAKE_READABLE((void *)k->pre_master, sizeof(k->pre_master));
    VALGRIND_MAKE_READABLE((void *)k->random1, sizeof(k->random1));
    VALGRIND_MAKE_READABLE((void *)k->random2, sizeof(k->random2));

    dmsg(D_SHOW_KEY_SOURCE,
         "%s pre_master: %s",
         prefix,
         format_hex(k->pre_master, sizeof(k->pre_master), 0, &gc));
    dmsg(D_SHOW_KEY_SOURCE,
         "%s random1: %s",
         prefix,
         format_hex(k->random1, sizeof(k->random1), 0, &gc));
    dmsg(D_SHOW_KEY_SOURCE,
         "%s random2: %s",
         prefix,
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
openvpn_PRF(const uint8_t *secret,
            int secret_len,
            const char *label,
            const uint8_t *client_seed,
            int client_seed_len,
            const uint8_t *server_seed,
            int server_seed_len,
            const struct session_id *client_sid,
            const struct session_id *server_sid,
            uint8_t *output,
            int output_len)
{
    /* concatenate seed components */

    struct buffer seed = alloc_buf(strlen(label)
                                   + client_seed_len
                                   + server_seed_len
                                   + SID_SIZE * 2);

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
    bool ret = ssl_tls1_PRF(BPTR(&seed), BLEN(&seed), secret, secret_len,
                            output, output_len);

    buf_clear(&seed);
    free_buf(&seed);

    VALGRIND_MAKE_READABLE((void *)output, output_len);
    return ret;
}

static void
init_key_contexts(struct key_state *ks,
                  struct tls_multi *multi,
                  const struct key_type *key_type,
                  bool server,
                  struct key2 *key2,
                  bool dco_enabled)
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

        int ret = init_key_dco_bi(multi, ks, key2, key_direction,
                                  key_type->cipher, server);
        if (ret < 0)
        {
            msg(M_FATAL, "Impossible to install key material in DCO: %s",
                strerror(-ret));
        }

        /* encrypt/decrypt context are unused with DCO */
        CLEAR(key->encrypt);
        CLEAR(key->decrypt);
        key->initialized = true;
    }
    else
    {
        init_key_ctx_bi(key, key2, key_direction, key_type, "Data Channel");
        /* Initialize implicit IVs */
        key_ctx_update_implicit_iv(&key->encrypt, key2->keys[(int)server].hmac,
                                   MAX_HMAC_KEY_LENGTH);
        key_ctx_update_implicit_iv(&key->decrypt,
                                   key2->keys[1 - (int)server].hmac,
                                   MAX_HMAC_KEY_LENGTH);
    }
}

static bool
generate_key_expansion_tls_export(struct tls_session *session, struct key2 *key2)
{
    if (!key_state_export_keying_material(session, EXPORT_KEY_DATA_LABEL,
                                          strlen(EXPORT_KEY_DATA_LABEL),
                                          key2->keys, sizeof(key2->keys)))
    {
        return false;
    }
    key2->n = 2;

    return true;
}

static bool
generate_key_expansion_openvpn_prf(const struct tls_session *session, struct key2 *key2)
{
    uint8_t master[48] = { 0 };

    const struct key_state *ks = &session->key[KS_PRIMARY];
    const struct key_source2 *key_src = ks->key_src;

    const struct session_id *client_sid = session->opt->server ?
                                          &ks->session_id_remote : &session->session_id;
    const struct session_id *server_sid = !session->opt->server ?
                                          &ks->session_id_remote : &session->session_id;

    /* debugging print of source key material */
    key_source2_print(key_src);

    /* compute master secret */
    if (!openvpn_PRF(key_src->client.pre_master,
                     sizeof(key_src->client.pre_master),
                     KEY_EXPANSION_ID " master secret",
                     key_src->client.random1,
                     sizeof(key_src->client.random1),
                     key_src->server.random1,
                     sizeof(key_src->server.random1),
                     NULL,
                     NULL,
                     master,
                     sizeof(master)))
    {
        return false;
    }

    /* compute key expansion */
    if (!openvpn_PRF(master,
                     sizeof(master),
                     KEY_EXPANSION_ID " key expansion",
                     key_src->client.random2,
                     sizeof(key_src->client.random2),
                     key_src->server.random2,
                     sizeof(key_src->server.random2),
                     client_sid,
                     server_sid,
                     (uint8_t *)key2->keys,
                     sizeof(key2->keys)))
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
generate_key_expansion(struct tls_multi *multi, struct key_state *ks,
                       struct tls_session *session)
{
    struct key_ctx_bi *key = &ks->crypto_options.key_ctx_bi;
    bool ret = false;
    struct key2 key2;

    if (key->initialized)
    {
        msg(D_TLS_ERRORS, "TLS Error: key already initialized");
        goto exit;
    }

    bool server = session->opt->server;

    if (session->opt->crypto_flags & CO_USE_TLS_KEY_MATERIAL_EXPORT)
    {
        if (!generate_key_expansion_tls_export(session, &key2))
        {
            msg(D_TLS_ERRORS, "TLS Error: Keying material export failed");
            goto exit;
        }
    }
    else
    {
        if (!generate_key_expansion_openvpn_prf(session, &key2))
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

    key2_print(&key2, &session->opt->key_type,
               "Master Encrypt", "Master Decrypt");

    /* check for weak keys */
    for (int i = 0; i < 2; ++i)
    {
        if (!check_key(&key2.keys[i], &session->opt->key_type))
        {
            msg(D_TLS_ERRORS, "TLS Error: Bad dynamic key generated");
            goto exit;
        }
    }

    init_key_contexts(ks, multi, &session->opt->key_type, server, &key2,
                      session->opt->dco_enabled);
    ret = true;

exit:
    secure_memzero(&key2, sizeof(key2));

    return ret;
}

static void
key_ctx_update_implicit_iv(struct key_ctx *ctx, uint8_t *key, size_t key_len)
{
    /* Only use implicit IV in AEAD cipher mode, where HMAC key is not used */
    if (cipher_ctx_mode_aead(ctx->cipher))
    {
        size_t impl_iv_len = 0;
        ASSERT(cipher_ctx_iv_length(ctx->cipher) >= OPENVPN_AEAD_MIN_IV_LEN);
        impl_iv_len = cipher_ctx_iv_length(ctx->cipher) - sizeof(packet_id_type);
        ASSERT(impl_iv_len <= OPENVPN_MAX_IV_LENGTH);
        ASSERT(impl_iv_len <= key_len);
        memcpy(ctx->implicit_iv, key, impl_iv_len);
        ctx->implicit_iv_len = impl_iv_len;
    }
}

/**
 * Generate data channel keys for the supplied TLS session.
 *
 * This erases the source material used to generate the data channel keys, and
 * can thus be called only once per session.
 */
bool
tls_session_generate_data_channel_keys(struct tls_multi *multi,
                                       struct tls_session *session)
{
    bool ret = false;
    struct key_state *ks = &session->key[KS_PRIMARY];   /* primary key */

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
    tls_limit_reneg_bytes(session->opt->key_type.cipher,
                          &session->opt->renegotiate_bytes);

    /* set the state of the keys for the session to generated */
    ks->state = S_GENERATED_KEYS;

    ret = true;
cleanup:
    secure_memzero(ks->key_src, sizeof(*ks->key_src));
    return ret;
}

bool
tls_session_update_crypto_params_do_work(struct tls_multi *multi,
                                         struct tls_session *session,
                                         struct options *options,
                                         struct frame *frame,
                                         struct frame *frame_fragment,
                                         struct link_socket_info *lsi)
{
    if (session->key[KS_PRIMARY].crypto_options.key_ctx_bi.initialized)
    {
        /* keys already generated, nothing to do */
        return true;

    }

    init_key_type(&session->opt->key_type, options->ciphername,
                  options->authname, true, true);

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

    if (session->key[KS_PRIMARY].key_id == 0
        && session->opt->crypto_flags & CO_USE_DYNAMIC_TLS_CRYPT)
    {
        /* If dynamic tls-crypt has been negotiated, and we are on the
         * first session (key_id = 0), generate a tls-crypt key for the
         * following renegotiations */
        if (!tls_session_generate_dynamic_tls_crypt_key(multi, session))
        {
            return false;
        }
    }
    return tls_session_generate_data_channel_keys(multi, session);
}

bool
tls_session_update_crypto_params(struct tls_multi *multi,
                                 struct tls_session *session,
                                 struct options *options, struct frame *frame,
                                 struct frame *frame_fragment,
                                 struct link_socket_info *lsi)
{
    if (!check_session_cipher(session, options))
    {
        return false;
    }

    /* Import crypto settings that might be set by pull/push */
    session->opt->crypto_flags |= options->imported_protocol_flags;

    return tls_session_update_crypto_params_do_work(multi, session, options,
                                                    frame, frame_fragment, lsi);
}


static bool
random_bytes_to_buf(struct buffer *buf,
                    uint8_t *out,
                    int outlen)
{
    if (!rand_bytes(out, outlen))
    {
        msg(M_FATAL, "ERROR: Random number generator cannot obtain entropy for key generation [SSL]");
    }
    if (!buf_write(buf, out, outlen))
    {
        return false;
    }
    return true;
}

static bool
key_source2_randomize_write(struct key_source2 *k2,
                            struct buffer *buf,
                            bool server)
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
key_source2_read(struct key_source2 *k2,
                 struct buffer *buf,
                 bool server)
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

static void
flush_payload_buffer(struct key_state *ks)
{
    struct buffer *b;

    while ((b = buffer_list_peek(ks->paybuf)))
    {
        key_state_write_plaintext_const(&ks->ks_ssl, b->data, b->len);
        buffer_list_pop(ks->paybuf);
    }
}

/*
 * Move the active key to the lame duck key and reinitialize the
 * active key.
 */
static void
key_state_soft_reset(struct tls_session *session)
{
    struct key_state *ks = &session->key[KS_PRIMARY];      /* primary key */
    struct key_state *ks_lame = &session->key[KS_LAME_DUCK]; /* retiring key */

    ks->must_die = now + session->opt->transition_window; /* remaining lifetime of old key */
    key_state_free(ks_lame, false);
    *ks_lame = *ks;

    key_state_init(session, ks);
    ks->session_id_remote = ks_lame->session_id_remote;
    ks->remote_addr = ks_lame->remote_addr;
}

void
tls_session_soft_reset(struct tls_multi *tls_multi)
{
    key_state_soft_reset(&tls_multi->session[TM_ACTIVE]);
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
    const int len = strlen(str) + 1;
    if (len < 1 || (maxlen >= 0 && len > maxlen))
    {
        return false;
    }
    if (!buf_write_u16(buf, len))
    {
        return false;
    }
    if (!buf_write(buf, str, len))
    {
        return false;
    }
    return true;
}

static bool
read_string(struct buffer *buf, char *str, const unsigned int capacity)
{
    const int len = buf_read_u16(buf);
    if (len < 1 || len > (int)capacity)
    {
        return false;
    }
    if (!buf_read(buf, str, len))
    {
        return false;
    }
    str[len-1] = '\0';
    return true;
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
    str = (char *) malloc(len);
    check_malloc_return(str);
    if (!buf_read(buf, str, len))
    {
        free(str);
        return NULL;
    }
    str[len-1] = '\0';
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
#elif defined(_WIN32)
        buf_printf(&out, "IV_PLAT=win\n");
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

        /* support for the --dns option */
        iv_proto |= IV_PROTO_DNS_OPTION;

        /* support for exit notify via control channel */
        iv_proto |= IV_PROTO_CC_EXIT_NOTIFY;

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

        buf_printf(&out, "IV_CIPHERS=%s\n", session->opt->config_ncp_ciphers);

#ifdef HAVE_EXPORT_KEYING_MATERIAL
        iv_proto |= IV_PROTO_TLS_KEY_EXPORT;
        iv_proto |= IV_PROTO_DYN_TLS_CRYPT;
#endif

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
            get_default_gateway(&rgi, session->opt->net_ctx);
            if (rgi.flags & RGI_HWADDR_DEFINED)
            {
                buf_printf(&out, "IV_HWADDR=%s\n", format_hex_ex(rgi.hwaddr, 6, 0, 1, ":", &gc));
            }
            buf_printf(&out, "IV_SSL=%s\n", get_ssl_library_version() );
#if defined(_WIN32)
            buf_printf(&out, "IV_PLAT_VER=%s\n", win32_version_string(&gc, false));
#endif
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
                         || (strncmp(e->string, "IV_SSO=", sizeof("IV_SSO=") - 1) == 0)
                         )
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

/**
 * Handle the writing of key data, peer-info, username/password, OCC
 * to the TLS control channel (cleartext).
 */
static bool
key_method_2_write(struct buffer *buf, struct tls_multi *multi, struct tls_session *session)
{
    struct key_state *ks = &session->key[KS_PRIMARY];      /* primary key */

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
                             session->opt->auth_user_pass_file_inline,
                             session->opt->sci);
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
            strncpynt(auth_token.username, up->username, USER_PASS_LEN);
        }
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

    if (session->opt->server && session->opt->mode != MODE_SERVER
        && ks->key_id == 0)
    {
        /* tls-server option set and not P2MP server, so we
         * are a P2P client running in tls-server mode */
        p2p_mode_ncp(multi, session);
    }

    return true;

error:
    msg(D_TLS_ERRORS, "TLS Error: Key Method #2 write failed");
    secure_memzero(ks->key_src, sizeof(*ks->key_src));
    return false;
}

static void
export_user_keying_material(struct key_state_ssl *ssl,
                            struct tls_session *session)
{
    if (session->opt->ekm_size > 0)
    {
        unsigned int size = session->opt->ekm_size;
        struct gc_arena gc = gc_new();

        unsigned char *ekm = gc_malloc(session->opt->ekm_size, true, &gc);
        if (key_state_export_keying_material(session,
                                             session->opt->ekm_label,
                                             session->opt->ekm_label_size,
                                             ekm, session->opt->ekm_size))
        {
            unsigned int len = (size * 2) + 2;

            const char *key = format_hex_ex(ekm, size, len, 0, NULL, &gc);
            setenv_str(session->opt->es, "exported_keying_material", key);

            dmsg(D_TLS_DEBUG_MED, "%s: exported keying material: %s",
                 __func__, key);
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
key_method_2_read(struct buffer *buf, struct tls_multi *multi, struct tls_session *session)
{
    struct key_state *ks = &session->key[KS_PRIMARY];      /* primary key */

    bool username_status, password_status;

    struct gc_arena gc = gc_new();
    char *options;
    struct user_pass *up = NULL;

    /* allocate temporary objects */
    ALLOC_ARRAY_CLEAR_GC(options, char, TLS_OPTIONS_LEN, &gc);

    /* discard leading uint32 */
    if (!buf_advance(buf, 4))
    {
        msg(D_TLS_ERRORS, "TLS ERROR: Plaintext buffer too short (%d bytes).",
            buf->len);
        goto error;
    }

    /* get key method */
    int key_method_flags = buf_read_u8(buf);
    if ((key_method_flags & KEY_METHOD_MASK) != 2)
    {
        msg(D_TLS_ERRORS,
            "TLS ERROR: Unknown key_method/flags=%d received from remote host",
            key_method_flags);
        goto error;
    }

    /* get key source material (not actual keys yet) */
    if (!key_source2_read(ks->key_src, buf, session->opt->server))
    {
        msg(D_TLS_ERRORS, "TLS Error: Error reading remote data channel key source entropy from plaintext buffer");
        goto error;
    }

    /* get options */
    if (!read_string(buf, options, TLS_OPTIONS_LEN))
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
    username_status = read_string(buf, up->username, USER_PASS_LEN);
    password_status = read_string(buf, up->password, USER_PASS_LEN);

    /* get peer info from control channel */
    free(multi->peer_info);
    multi->peer_info = read_string_alloc(buf);
    if (multi->peer_info)
    {
        output_peer_info_env(session->opt->es, multi->peer_info);
    }

    free(multi->remote_ciphername);
    multi->remote_ciphername =
        options_string_extract_option(options, "cipher", NULL);
    multi->remote_usescomp = strstr(options, ",comp-lzo,");

    /* In OCC we send '[null-cipher]' instead 'none' */
    if (multi->remote_ciphername
        && strcmp(multi->remote_ciphername, "[null-cipher]") == 0)
    {
        free(multi->remote_ciphername);
        multi->remote_ciphername = string_alloc("none", NULL);
    }

    if (tls_session_user_pass_enabled(session))
    {
        /* Perform username/password authentication */
        if (!username_status || !password_status)
        {
            CLEAR(*up);
            if (!(session->opt->ssl_flags & SSLF_AUTH_USER_PASS_OPTIONAL))
            {
                msg(D_TLS_ERRORS, "TLS Error: Auth Username/Password was not provided by peer");
                goto error;
            }
        }

        verify_user_pass(up, multi, session);
    }
    else
    {
        /* Session verification should have occurred during TLS negotiation*/
        if (!session->verified)
        {
            msg(D_TLS_ERRORS,
                "TLS Error: Certificate verification failed (key-method 2)");
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

        if (session->opt->ssl_flags & SSLF_OPT_VERIFY)
        {
            msg(D_TLS_ERRORS, "Option inconsistency warnings triggering disconnect due to --opt-verify");
            ks->authenticated = KS_AUTH_FALSE;
        }
    }

    buf_clear(buf);

    /*
     * Call OPENVPN_PLUGIN_TLS_FINAL plugin if defined, for final
     * veto opportunity over authentication decision.
     */
    if ((ks->authenticated > KS_AUTH_FALSE)
        && plugin_defined(session->opt->plugins, OPENVPN_PLUGIN_TLS_FINAL))
    {
        export_user_keying_material(&ks->ks_ssl, session);

        if (plugin_call(session->opt->plugins, OPENVPN_PLUGIN_TLS_FINAL, NULL, NULL, session->opt->es) != OPENVPN_PLUGIN_FUNC_SUCCESS)
        {
            ks->authenticated = KS_AUTH_FALSE;
        }

        setenv_del(session->opt->es, "exported_keying_material");
    }

    if (!session->opt->server && !session->opt->pull && ks->key_id == 0)
    {
        /* We are a p2p tls-client without pull, enable common
         * protocol options */
        p2p_mode_ncp(multi, session);
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
    gc_free(&gc);
    return false;
}

static int
auth_deferred_expire_window(const struct tls_options *o)
{
    int ret = o->handshake_window;
    const int r2 = o->renegotiate_seconds / 2;

    if (o->renegotiate_seconds && r2 < ret)
    {
        ret = r2;
    }
    return ret;
}

/**
 * Move the session from S_INITIAL to S_PRE_START. This will also generate
 * the initial message based on ks->initial_opcode
 *
 * @return if the state change was succesful
 */
static bool
session_move_pre_start(const struct tls_session *session,
                       struct key_state *ks, bool skip_initial_send)
{
    struct buffer *buf = reliable_get_buf_output_sequenced(ks->send_reliable);
    if (!buf)
    {
        return false;
    }

    ks->initial = now;
    ks->must_negotiate = now + session->opt->handshake_window;
    ks->auth_deferred_expire = now + auth_deferred_expire_window(session->opt);

    /* null buffer */
    reliable_mark_active_outgoing(ks->send_reliable, buf, ks->initial_opcode);

    /* If we want to skip sending the initial handshake packet we still generate
     * it to increase internal counters etc. but immediately mark it as done */
    if (skip_initial_send)
    {
        reliable_mark_deleted(ks->send_reliable, buf);
    }
    INCR_GENERATED;

    ks->state = S_PRE_START;

    struct gc_arena gc = gc_new();
    dmsg(D_TLS_DEBUG, "TLS: Initial Handshake, sid=%s",
         session_id_print(&session->session_id, &gc));
    gc_free(&gc);

#ifdef ENABLE_MANAGEMENT
    if (management && ks->initial_opcode != P_CONTROL_SOFT_RESET_V1)
    {
        management_set_state(management,
                             OPENVPN_STATE_WAIT,
                             NULL,
                             NULL,
                             NULL,
                             NULL,
                             NULL);
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
                    struct link_socket_info *to_link_socket_info,
                    struct key_state *ks)
{
    dmsg(D_TLS_DEBUG_MED, "STATE S_ACTIVE");

    ks->established = now;
    if (check_debug_level(D_HANDSHAKE))
    {
        print_details(&ks->ks_ssl, "Control Channel:");
    }
    ks->state = S_ACTIVE;
    /* Cancel negotiation timeout */
    ks->must_negotiate = 0;
    INCR_SUCCESS;

    /* Set outgoing address for data channel packets */
    link_socket_set_outgoing_addr(to_link_socket_info, &ks->remote_addr,
                                  session->common_name, session->opt->es);

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

    /* Flush any payload packets that were buffered before our state transitioned to S_ACTIVE */
    flush_payload_buffer(ks);

#ifdef MEASURE_TLS_HANDSHAKE_STATS
    show_tls_performance_stats();
#endif
}

bool
session_skip_to_pre_start(struct tls_session *session,
                          struct tls_pre_decrypt_state *state,
                          struct link_socket_actual *from)
{
    struct key_state *ks = &session->key[KS_PRIMARY];
    ks->session_id_remote = state->peer_session_id;
    ks->remote_addr = *from;
    session->session_id = state->server_session_id;
    session->untrusted_addr = *from;
    session->burst = true;

    /* The OpenVPN protocol implicitly mandates that packet id always start
     * from 0 in the RESET packets as OpenVPN 2.x will not allow gaps in the
     * ids and starts always from 0. Since we skip/ignore one (RESET) packet
     * in each direction, we need to set the ids to 1 */
    ks->rec_reliable->packet_id = 1;
    /* for ks->send_reliable->packet_id, session_move_pre_start moves the
     * counter to 1 */
    session->tls_wrap.opt.packet_id.send.id = 1;
    return session_move_pre_start(session, ks, true);
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
        uint16_t type = buf_read_u16(buf);
        uint16_t len = buf_read_u16(buf);
        if (buf_len(buf) < len)
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
                uint16_t flags = buf_read_u16(buf);

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
    reliable_mark_deleted(ks->rec_reliable, buf);

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
read_incoming_tls_ciphertext(struct buffer *buf, struct key_state *ks,
                             bool *continue_tls_process)
{
    int status = 0;
    if (buf->len)
    {
        status = key_state_write_ciphertext(&ks->ks_ssl, buf);
        if (status == -1)
        {
            msg(D_TLS_ERRORS,
                "TLS Error: Incoming Ciphertext -> TLS object write error");
            return false;
        }
    }
    else
    {
        status = 1;
    }
    if (status == 1)
    {
        reliable_mark_deleted(ks->rec_reliable, buf);
        *continue_tls_process = true;
        dmsg(D_TLS_DEBUG, "Incoming Ciphertext -> TLS");
    }
    return true;
}

static bool
control_packet_needs_wkc(const struct key_state *ks)
{
    return (ks->crypto_options.flags & CO_RESEND_WKC)
           && (ks->send_reliable->packet_id == 1);
}


static bool
read_incoming_tls_plaintext(struct key_state *ks, struct buffer *buf,
                            interval_t *wakeup, bool *continue_tls_process)
{
    ASSERT(buf_init(buf, 0));

    int status = key_state_read_plaintext(&ks->ks_ssl, buf);

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

static bool
write_outgoing_tls_ciphertext(struct tls_session *session, bool *continue_tls_process)
{
    struct key_state *ks = &session->key[KS_PRIMARY];

    int rel_avail = reliable_get_num_output_sequenced_available(ks->send_reliable);
    if (rel_avail == 0)
    {
        return true;
    }

    /* We need to determine how much space is actually available in the control
     * channel frame */
    int max_pkt_len = min_int(TLS_CHANNEL_BUF_SIZE, session->opt->frame.tun_mtu);

    /* Subtract overhead */
    max_pkt_len -= calc_control_channel_frame_overhead(session);

    /* calculate total available length for outgoing tls ciphertext */
    int maxlen = max_pkt_len * rel_avail;

    /* Is first packet one that will have a WKC appended? */
    if (control_packet_needs_wkc(ks))
    {
        maxlen -= buf_len(session->tls_wrap.tls_crypt_v2_wkc);
    }

    /* If we end up with a size that leaves no room for payload, ignore the
     * constraints to still be to send a packet. This might have gone negative
     * if we have a large wrapped client key. */
    if (maxlen < 16)
    {
        msg(D_TLS_ERRORS, "Warning: --max-packet-size (%d) setting too low. "
            "Sending minimum sized packet.",
            session->opt->frame.tun_mtu);
        maxlen = 16;
        /* We set the maximum length here to ensure a packet with a wrapped
         * key can actually carry the 16 byte of payload */
        max_pkt_len = TLS_CHANNEL_BUF_SIZE;
    }

    /* This seems a bit wasteful to allocate every time */
    struct gc_arena gc = gc_new();
    struct buffer tmp = alloc_buf_gc(maxlen, &gc);

    int status = key_state_read_ciphertext(&ks->ks_ssl, &tmp);

    if (status == -1)
    {
        msg(D_TLS_ERRORS,
            "TLS Error: Ciphertext -> reliable TCP/UDP transport read error");
        gc_free(&gc);
        return false;
    }
    if (status == 1)
    {
        /* Split the TLS ciphertext (TLS record) into multiple small packets
         * that respect tls_mtu */
        while (tmp.len > 0)
        {
            int len = max_pkt_len;
            int opcode = P_CONTROL_V1;
            if (control_packet_needs_wkc(ks))
            {
                opcode = P_CONTROL_WKC_V1;
                len = max_int(0, len - buf_len(session->tls_wrap.tls_crypt_v2_wkc));
            }
            /* do not send more than available */
            len = min_int(len, tmp.len);

            struct buffer *buf = reliable_get_buf_output_sequenced(ks->send_reliable);
            /* we assert here since we checked for its availability before */
            ASSERT(buf);
            buf_copy_n(buf, &tmp, len);

            reliable_mark_active_outgoing(ks->send_reliable, buf, opcode);
            INCR_GENERATED;
            *continue_tls_process = true;
        }
        dmsg(D_TLS_DEBUG, "Outgoing Ciphertext -> Reliable");
    }

    gc_free(&gc);
    return true;
}

static bool
tls_process_state(struct tls_multi *multi,
                  struct tls_session *session,
                  struct buffer *to_link,
                  struct link_socket_actual **to_link_addr,
                  struct link_socket_info *to_link_socket_info,
                  interval_t *wakeup)
{
    /* This variable indicates if we should call this method
     * again to process more incoming/outgoing TLS state/data
     * We want to repeat this until we either determined that there
     * is nothing more to process or that further processing
     * should only be done after the outer loop (sending packets etc.)
     * has run once more */
    bool continue_tls_process = false;
    struct key_state *ks = &session->key[KS_PRIMARY];      /* primary key */

    /* Initial handshake */
    if (ks->state == S_INITIAL)
    {
        continue_tls_process = session_move_pre_start(session, ks, false);
    }

    /* Are we timed out on receive? */
    if (now >= ks->must_negotiate && ks->state < S_ACTIVE)
    {
        msg(D_TLS_ERRORS,
            "TLS Error: TLS key negotiation failed to occur within %d seconds (check your network connectivity)",
            session->opt->handshake_window);
        goto error;
    }

    /* Check if the initial three-way Handshake is complete.
     * We consider the handshake to be complete when our own initial
     * packet has been successfully ACKed. */
    if (ks->state == S_PRE_START && reliable_empty(ks->send_reliable))
    {
        ks->state = S_START;
        continue_tls_process = true;

        /* New connection, remove any old X509 env variables */
        tls_x509_clear_env(session->opt->es);
        dmsg(D_TLS_DEBUG_MED, "STATE S_START");
    }

    /* Wait for ACK */
    if (((ks->state == S_GOT_KEY && !session->opt->server)
         || (ks->state == S_SENT_KEY && session->opt->server))
        && reliable_empty(ks->send_reliable))
    {
        session_move_active(multi, session, to_link_socket_info, ks);
        continue_tls_process = true;
    }

    /* Reliable buffer to outgoing TCP/UDP (send up to CONTROL_SEND_ACK_MAX ACKs
     * for previously received packets) */
    if (!to_link->len && reliable_can_send(ks->send_reliable))
    {
        int opcode;

        struct buffer *buf = reliable_send(ks->send_reliable, &opcode);
        ASSERT(buf);
        struct buffer b = *buf;
        INCR_SENT;

        write_control_auth(session, ks, &b, to_link_addr, opcode,
                           CONTROL_SEND_ACK_MAX, true);
        *to_link = b;
        dmsg(D_TLS_DEBUG, "Reliable -> TCP/UDP");

        /* This changed the state of the outgoing buffer. In order to avoid
         * running this function again/further and invalidating the key_state
         * buffer and accessing the buffer that is now in to_link after it being
         * freed for a potential error, we shortcircuit exiting of the outer
         * process here. */
        return false;
    }

    /* Write incoming ciphertext to TLS object */
    struct reliable_entry *entry = reliable_get_entry_sequenced(ks->rec_reliable);
    if (entry)
    {
        /* The first packet from the peer (the reset packet) is special and
         * contains early protocol negotiation */
        if (entry->packet_id == 0 && is_hard_reset_method2(entry->opcode))
        {
            if (!parse_early_negotiation_tlvs(&entry->buf, ks))
            {
                goto error;
            }
        }
        else
        {
            if (!read_incoming_tls_ciphertext(&entry->buf, ks, &continue_tls_process))
            {
                goto error;
            }
        }
    }

    /* Read incoming plaintext from TLS object */
    struct buffer *buf = &ks->plaintext_read_buf;
    if (!buf->len)
    {
        if (!read_incoming_tls_plaintext(ks, buf, wakeup, &continue_tls_process))
        {
            goto error;
        }
    }

    /* Send Key */
    buf = &ks->plaintext_write_buf;
    if (!buf->len && ((ks->state == S_START && !session->opt->server)
                      || (ks->state == S_GOT_KEY && session->opt->server)))
    {
        if (!key_method_2_write(buf, multi, session))
        {
            goto error;
        }

        continue_tls_process = true;
        dmsg(D_TLS_DEBUG_MED, "STATE S_SENT_KEY");
        ks->state = S_SENT_KEY;
    }

    /* Receive Key */
    buf = &ks->plaintext_read_buf;
    if (buf->len
        && ((ks->state == S_SENT_KEY && !session->opt->server)
            || (ks->state == S_START && session->opt->server)))
    {
        if (!key_method_2_read(buf, multi, session))
        {
            goto error;
        }

        continue_tls_process = true;
        dmsg(D_TLS_DEBUG_MED, "STATE S_GOT_KEY");
        ks->state = S_GOT_KEY;
    }

    /* Write outgoing plaintext to TLS object */
    buf = &ks->plaintext_write_buf;
    if (buf->len)
    {
        int status = key_state_write_plaintext(&ks->ks_ssl, buf);
        if (status == -1)
        {
            msg(D_TLS_ERRORS,
                "TLS ERROR: Outgoing Plaintext -> TLS object write error");
            goto error;
        }
        if (status == 1)
        {
            continue_tls_process = true;
            dmsg(D_TLS_DEBUG, "Outgoing Plaintext -> TLS");
        }
    }

    /* Outgoing Ciphertext to reliable buffer */
    if (ks->state >= S_START)
    {
        buf = reliable_get_buf_output_sequenced(ks->send_reliable);
        if (buf)
        {
            if (!write_outgoing_tls_ciphertext(session, &continue_tls_process))
            {
                goto error;
            }
        }
    }

    return continue_tls_process;
error:
    tls_clear_error();
    ks->state = S_ERROR;
    msg(D_TLS_ERRORS, "TLS Error: TLS handshake failed");
    INCR_ERROR;
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
tls_process(struct tls_multi *multi,
            struct tls_session *session,
            struct buffer *to_link,
            struct link_socket_actual **to_link_addr,
            struct link_socket_info *to_link_socket_info,
            interval_t *wakeup)
{
    struct key_state *ks = &session->key[KS_PRIMARY];      /* primary key */
    struct key_state *ks_lame = &session->key[KS_LAME_DUCK]; /* retiring key */

    /* Make sure we were initialized and that we're not in an error state */
    ASSERT(ks->state != S_UNDEF);
    ASSERT(ks->state != S_ERROR);
    ASSERT(session_id_defined(&session->session_id));

    /* Should we trigger a soft reset? -- new key, keeps old key for a while */
    if (ks->state >= S_GENERATED_KEYS
        && ((session->opt->renegotiate_seconds
             && now >= ks->established + session->opt->renegotiate_seconds)
            || (session->opt->renegotiate_bytes > 0
                && ks->n_bytes >= session->opt->renegotiate_bytes)
            || (session->opt->renegotiate_packets
                && ks->n_packets >= session->opt->renegotiate_packets)
            || (packet_id_close_to_wrapping(&ks->crypto_options.packet_id.send))))
    {
        msg(D_TLS_DEBUG_LOW, "TLS: soft reset sec=%d/%d bytes=" counter_format
            "/%d pkts=" counter_format "/%d",
            (int) (now - ks->established), session->opt->renegotiate_seconds,
            ks->n_bytes, session->opt->renegotiate_bytes,
            ks->n_packets, session->opt->renegotiate_packets);
        key_state_soft_reset(session);
    }

    /* Kill lame duck key transition_window seconds after primary key negotiation */
    if (lame_duck_must_die(session, wakeup))
    {
        key_state_free(ks_lame, true);
        msg(D_TLS_DEBUG_LOW, "TLS: tls_process: killed expiring key");
    }

    bool continue_tls_process = true;
    while (continue_tls_process)
    {
        update_time();

        dmsg(D_TLS_DEBUG, "TLS: tls_process: chg=%d ks=%s lame=%s to_link->len=%d wakeup=%d",
             continue_tls_process,
             state_name(ks->state),
             state_name(ks_lame->state),
             to_link->len,
             *wakeup);
        continue_tls_process = tls_process_state(multi, session, to_link, to_link_addr,
                                                 to_link_socket_info, wakeup);

        if (ks->state == S_ERROR)
        {
            return false;
        }

    }

    update_time();

    /* We often send acks back to back to a following control packet. This
     * normally does not create a problem (apart from an extra packet).
     * However, with the P_CONTROL_WKC_V1 we need to ensure that the packet
     * gets resent if not received by remote, so instead we use an empty
     * control packet in this special case */

    /* Send 1 or more ACKs (each received control packet gets one ACK) */
    if (!to_link->len && !reliable_ack_empty(ks->rec_ack))
    {
        if (control_packet_needs_wkc(ks))
        {
            struct buffer *buf = reliable_get_buf_output_sequenced(ks->send_reliable);
            if (!buf)
            {
                return false;
            }

            /* We do not write anything to the buffer, this way this will be
             * an empty control packet that gets the ack piggybacked and
             * also appended the wrapped client key since it has a WCK opcode */
            reliable_mark_active_outgoing(ks->send_reliable, buf, P_CONTROL_WKC_V1);
        }
        else
        {
            struct buffer buf = ks->ack_write_buf;
            ASSERT(buf_init(&buf, multi->opt.frame.buf.headroom));
            write_control_auth(session, ks, &buf, to_link_addr, P_ACK_V1,
                               RELIABLE_ACK_SIZE, false);
            *to_link = buf;
            dmsg(D_TLS_DEBUG, "Dedicated ACK -> TCP/UDP");
        }
    }

    /* When should we wake up again? */
    if (ks->state >= S_INITIAL)
    {
        compute_earliest_wakeup(wakeup,
                                reliable_send_timeout(ks->send_reliable));

        if (ks->must_negotiate)
        {
            compute_earliest_wakeup(wakeup, ks->must_negotiate - now);
        }
    }

    if (ks->established && session->opt->renegotiate_seconds)
    {
        compute_earliest_wakeup(wakeup,
                                ks->established + session->opt->renegotiate_seconds - now);
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

    for (int i = 0; i < KS_SIZE; i++)
    {
        struct key_state *ks = &session->key[i];
        if (ks->state == S_UNDEF)
        {
            continue;
        }

        /* we don't expect send_reliable to be NULL when state is
         * not S_UNDEF, but people have reported crashes nonetheless,
         * therefore we better catch this event, report and exit.
         */
        if (!ks->send_reliable)
        {
            msg(M_FATAL, "ERROR: session->key[%d]->send_reliable is NULL "
                "while key state is %s. Exiting.",
                i, state_name(ks->state));
        }

        for (int j = 0; j < ks->send_reliable->size; j++)
        {
            if (ks->send_reliable->array[j].buf.data == dataptr)
            {
                msg(M_INFO, "Warning buffer of freed TLS session is still in"
                    " use (session->key[%d].send_reliable->array[%d])",
                    i, j);

                goto used;
            }
        }
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
tls_multi_process(struct tls_multi *multi,
                  struct buffer *to_link,
                  struct link_socket_actual **to_link_addr,
                  struct link_socket_info *to_link_socket_info,
                  interval_t *wakeup)
{
    struct gc_arena gc = gc_new();
    int active = TLSMP_INACTIVE;
    bool error = false;

    perf_push(PERF_TLS_MULTI_PROCESS);

    tls_clear_error();

    /*
     * Process each session object having state of S_INITIAL or greater,
     * and which has a defined remote IP addr.
     */

    for (int i = 0; i < TM_SIZE; ++i)
    {
        struct tls_session *session = &multi->session[i];
        struct key_state *ks = &session->key[KS_PRIMARY];
        struct key_state *ks_lame = &session->key[KS_LAME_DUCK];

        /* set initial remote address. This triggers connecting with that
         * session. So we only do that if the TM_ACTIVE session is not
         * established */
        if (i == TM_INITIAL && ks->state == S_INITIAL
            && get_primary_key(multi)->state <= S_INITIAL
            && link_socket_actual_defined(&to_link_socket_info->lsa->actual))
        {
            ks->remote_addr = to_link_socket_info->lsa->actual;
        }

        dmsg(D_TLS_DEBUG,
             "TLS: tls_multi_process: i=%d state=%s, mysid=%s, stored-sid=%s, stored-ip=%s",
             i,
             state_name(ks->state),
             session_id_print(&session->session_id, &gc),
             session_id_print(&ks->session_id_remote, &gc),
             print_link_socket_actual(&ks->remote_addr, &gc));

        if (ks->state >= S_INITIAL && link_socket_actual_defined(&ks->remote_addr))
        {
            struct link_socket_actual *tla = NULL;

            update_time();

            if (tls_process(multi, session, to_link, &tla,
                            to_link_socket_info, wakeup))
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

                if (i == TM_ACTIVE
                    || (i == TM_INITIAL && get_primary_key(multi)->state < S_ACTIVE))
                {
                    error = true;
                }

                if (i == TM_ACTIVE
                    && ks_lame->state >= S_GENERATED_KEYS
                    && !multi->opt.single_session)
                {
                    move_session(multi, TM_LAME_DUCK, TM_ACTIVE, true);
                }
                else
                {
                    check_session_buf_not_used(to_link, session);
                    reset_session(multi, session);
                }
            }
        }
    }

    update_time();

    enum tls_auth_status tas = tls_authentication_status(multi);

    /* If we have successfully authenticated and are still waiting for the authentication to finish
     * move the state machine for the multi context forward */

    if (multi->multi_state >= CAS_CONNECT_DONE)
    {
        /* Only generate keys for the TM_ACTIVE session. We defer generating
         * keys for TM_INITIAL until we actually trust it.
         * For TM_LAME_DUCK it makes no sense to generate new keys. */
        struct tls_session *session = &multi->session[TM_ACTIVE];
        struct key_state *ks = &session->key[KS_PRIMARY];

        if (ks->state == S_ACTIVE && ks->authenticated == KS_AUTH_TRUE)
        {
            /* Session is now fully authenticated.
            * tls_session_generate_data_channel_keys will move ks->state
            * from S_ACTIVE to S_GENERATED_KEYS */
            if (!tls_session_generate_data_channel_keys(multi, session))
            {
                msg(D_TLS_ERRORS, "TLS Error: generate_key_expansion failed");
                ks->authenticated = KS_AUTH_FALSE;
                ks->state = S_ERROR;
            }

            /* Update auth token on the client if needed on renegotiation
             * (key id !=0) */
            if (session->key[KS_PRIMARY].key_id != 0)
            {
                resend_auth_token_renegotiation(multi, session);
            }
        }
    }

    if (multi->multi_state == CAS_WAITING_AUTH && tas == TLS_AUTHENTICATION_SUCCEEDED)
    {
        multi->multi_state = CAS_PENDING;
    }

    /*
     * If lame duck session expires, kill it.
     */
    if (lame_duck_must_die(&multi->session[TM_LAME_DUCK], wakeup))
    {
        tls_session_free(&multi->session[TM_LAME_DUCK], true);
        msg(D_TLS_DEBUG_LOW, "TLS: tls_multi_process: killed expiring key");
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
    if (TLS_AUTHENTICATED(multi, &multi->session[TM_INITIAL].key[KS_PRIMARY]))
    {
        move_session(multi, TM_ACTIVE, TM_INITIAL, true);
        tas = tls_authentication_status(multi);
        msg(D_TLS_DEBUG_LOW, "TLS: tls_multi_process: initial untrusted "
            "session promoted to %strusted",
            tas == TLS_AUTHENTICATION_SUCCEEDED ? "" : "semi-");

        if (multi->multi_state == CAS_CONNECT_DONE)
        {
            multi->multi_state = CAS_RECONNECT_PENDING;
            active = TLSMP_RECONNECT;
        }
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

    perf_pop();
    gc_free(&gc);

    return (tas == TLS_AUTHENTICATION_FAILED) ? TLSMP_KILL : active;
}

/**
 * We have not found a matching key to decrypt data channel packet,
 * try to generate a sensible error message and print it
 */
static void
print_key_id_not_found_reason(struct tls_multi *multi,
                              const struct link_socket_actual *from, int key_id)
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
            msg(D_MULTI_DROPPED,
                "Key %s [%d] not initialized (yet), dropping packet.",
                source, key_id);
            gc_free(&gc);
            return;
        }
        if (ks->state >= S_ACTIVE && ks->authenticated != KS_AUTH_TRUE)
        {
            msg(D_MULTI_DROPPED,
                "Key %s [%d] not authorized%s, dropping packet.",
                source, key_id,
                (ks->authenticated == KS_AUTH_DEFERRED) ? " (deferred)" : "");
            gc_free(&gc);
            return;
        }
    }

    msg(D_TLS_ERRORS,
        "TLS Error: local/remote TLS keys are out of sync: %s "
        "(received key id: %d, known key ids: %s)",
        source, key_id,
        print_key_id(multi, &gc));
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
handle_data_channel_packet(struct tls_multi *multi,
                           const struct link_socket_actual *from,
                           struct buffer *buf,
                           struct crypto_options **opt,
                           bool floated,
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
        if (ks->state >= S_GENERATED_KEYS && key_id == ks->key_id
            && ks->authenticated == KS_AUTH_TRUE
            && (floated || link_socket_actual_match(from, &ks->remote_addr)))
        {
            ASSERT(ks->crypto_options.key_ctx_bi.initialized);
            /* return appropriate data channel decrypt key in opt */
            *opt = &ks->crypto_options;
            if (op == P_DATA_V2)
            {
                *ad_start = BPTR(buf);
            }
            ASSERT(buf_advance(buf, 1));
            if (op == P_DATA_V1)
            {
                *ad_start = BPTR(buf);
            }
            else if (op == P_DATA_V2)
            {
                if (buf->len < 4)
                {
                    msg(D_TLS_ERRORS, "Protocol error: received P_DATA_V2 from %s but length is < 4",
                        print_link_socket_actual(from, &gc));
                    ++multi->n_soft_errors;
                    goto done;
                }
                ASSERT(buf_advance(buf, 3));
            }

            ++ks->n_packets;
            ks->n_bytes += buf->len;
            dmsg(D_TLS_KEYSELECT,
                 "TLS: tls_pre_decrypt, key_id=%d, IP=%s",
                 key_id, print_link_socket_actual(from, &gc));
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
tls_pre_decrypt(struct tls_multi *multi,
                const struct link_socket_actual *from,
                struct buffer *buf,
                struct crypto_options **opt,
                bool floated,
                const uint8_t **ad_start)
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

    if ((op == P_DATA_V1) || (op == P_DATA_V2))
    {
        handle_data_channel_packet(multi, from, buf, opt, floated, ad_start);
        return false;
    }

    /* get key_id */
    int key_id = pkt_firstbyte & P_KEY_ID_MASK;

    /* control channel packet */
    bool do_burst = false;
    bool new_link = false;
    struct session_id sid;         /* remote session ID */

    /* verify legal opcode */
    if (op < P_FIRST_OPCODE || op > P_LAST_OPCODE)
    {
        if (op == P_CONTROL_HARD_RESET_CLIENT_V1
            || op == P_CONTROL_HARD_RESET_SERVER_V1)
        {
            msg(D_TLS_ERRORS, "Peer tried unsupported key-method 1");
        }
        msg(D_TLS_ERRORS,
            "TLS Error: unknown opcode received from %s op=%d",
            print_link_socket_actual(from, &gc), op);
        goto error;
    }

    /* hard reset ? */
    if (is_hard_reset_method2(op))
    {
        /* verify client -> server or server -> client connection */
        if (((op == P_CONTROL_HARD_RESET_CLIENT_V2
              || op == P_CONTROL_HARD_RESET_CLIENT_V3) && !multi->opt.server)
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
    dmsg(D_TLS_DEBUG, "TLS: control channel, op=%s, IP=%s",
         packet_opcode_name(op), print_link_socket_actual(from, &gc));

    /* get remote session-id */
    {
        struct buffer tmp = *buf;
        buf_advance(&tmp, 1);
        if (!session_id_read(&sid, &tmp) || !session_id_defined(&sid))
        {
            msg(D_TLS_ERRORS,
                "TLS Error: session-id not found in packet from %s",
                print_link_socket_actual(from, &gc));
            goto error;
        }
    }

    int i;
    /* use session ID to match up packet with appropriate tls_session object */
    for (i = 0; i < TM_SIZE; ++i)
    {
        struct tls_session *session = &multi->session[i];
        struct key_state *ks = &session->key[KS_PRIMARY];

        dmsg(D_TLS_DEBUG,
             "TLS: initial packet test, i=%d state=%s, mysid=%s, rec-sid=%s, rec-ip=%s, stored-sid=%s, stored-ip=%s",
             i,
             state_name(ks->state),
             session_id_print(&session->session_id, &gc),
             session_id_print(&sid, &gc),
             print_link_socket_actual(from, &gc),
             session_id_print(&ks->session_id_remote, &gc),
             print_link_socket_actual(&ks->remote_addr, &gc));

        if (session_id_equal(&ks->session_id_remote, &sid))
        /* found a match */
        {
            if (i == TM_LAME_DUCK)
            {
                msg(D_TLS_ERRORS,
                    "TLS ERROR: received control packet with stale session-id=%s",
                    session_id_print(&sid, &gc));
                goto error;
            }
            dmsg(D_TLS_DEBUG,
                 "TLS: found match, session[%d], sid=%s",
                 i, session_id_print(&sid, &gc));
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
        struct tls_session *session = &multi->session[TM_INITIAL];

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

        if (!read_control_auth(buf, tls_session_get_tls_wrap(session, key_id), from,
                               session->opt))
        {
            goto error;
        }

#ifdef ENABLE_MANAGEMENT
        if (management)
        {
            management_set_state(management,
                                 OPENVPN_STATE_AUTH,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL);
        }
#endif

        /*
         * New session-initiating control packet is authenticated at this point,
         * assuming that the --tls-auth command line option was used.
         *
         * Without --tls-auth, we leave authentication entirely up to TLS.
         */
        msg(D_TLS_DEBUG_LOW,
            "TLS: Initial packet from %s, sid=%s",
            print_link_socket_actual(from, &gc),
            session_id_print(&sid, &gc));

        do_burst = true;
        new_link = true;
        i = TM_INITIAL;
        session->untrusted_addr = *from;
    }
    else
    {
        struct tls_session *session = &multi->session[i];
        struct key_state *ks = &session->key[KS_PRIMARY];

        /*
         * Packet must belong to an existing session.
         */
        if (i != TM_ACTIVE && i != TM_INITIAL)
        {
            msg(D_TLS_ERRORS,
                "TLS Error: Unroutable control packet received from %s (si=%d op=%s)",
                print_link_socket_actual(from, &gc),
                i,
                packet_opcode_name(op));
            goto error;
        }

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
            if (!read_control_auth(buf, tls_session_get_tls_wrap(session, key_id),
                                   from, session->opt))
            {
                goto error;
            }

            key_state_soft_reset(session);

            dmsg(D_TLS_DEBUG,
                 "TLS: received P_CONTROL_SOFT_RESET_V1 s=%d sid=%s",
                 i, session_id_print(&sid, &gc));
        }
        else
        {
            /*
             * Remote responding to our key renegotiation request?
             */
            if (op == P_CONTROL_SOFT_RESET_V1)
            {
                do_burst = true;
            }

            if (!read_control_auth(buf, tls_session_get_tls_wrap(session, key_id),
                                   from, session->opt))
            {
                goto error;
            }

            dmsg(D_TLS_DEBUG,
                 "TLS: received control channel packet s#=%d sid=%s",
                 i, session_id_print(&sid, &gc));
        }
    }

    /*
     * We have an authenticated control channel packet (if --tls-auth/tls-crypt
     * or tls-crypt-v2 was set).
     * Now pass to our reliability layer which deals with
     * packet acknowledgements, retransmits, sequencing, etc.
     */
    struct tls_session *session = &multi->session[i];
    struct key_state *ks = &session->key[KS_PRIMARY];

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
        ks->remote_addr = *from;
        ++multi->n_sessions;
    }
    else if (!link_socket_actual_match(&ks->remote_addr, from))
    {
        msg(D_TLS_ERRORS,
            "TLS Error: Existing session control channel packet from unknown IP address: %s",
            print_link_socket_actual(from, &gc));
        goto error;
    }

    /*
     * Should we do a retransmit of all unacknowledged packets in
     * the send buffer?  This improves the start-up efficiency of the
     * initial key negotiation after the 2nd peer comes online.
     */
    if (do_burst && !session->burst)
    {
        reliable_schedule_now(ks->send_reliable);
        session->burst = true;
    }

    /* Check key_id */
    if (ks->key_id != key_id)
    {
        msg(D_TLS_ERRORS,
            "TLS ERROR: local/remote key IDs out of sync (%d/%d) ID: %s",
            ks->key_id, key_id, print_key_id(multi, &gc));
        goto error;
    }

    /*
     * Process incoming ACKs for packets we can now
     * delete from reliable send buffer
     */
    {
        /* buffers all packet IDs to delete from send_reliable */
        struct reliable_ack send_ack;

        if (!reliable_ack_read(&send_ack, buf, &session->session_id))
        {
            msg(D_TLS_ERRORS,
                "TLS Error: reading acknowledgement record from packet");
            goto error;
        }
        reliable_send_purge(ks->send_reliable, &send_ack);
    }

    if (op != P_ACK_V1 && reliable_can_get(ks->rec_reliable))
    {
        packet_id_type id;

        /* Extract the packet ID from the packet */
        if (reliable_ack_read_packet_id(buf, &id))
        {
            /* Avoid deadlock by rejecting packet that would de-sequentialize receive buffer */
            if (reliable_wont_break_sequentiality(ks->rec_reliable, id))
            {
                if (reliable_not_replay(ks->rec_reliable, id))
                {
                    /* Save incoming ciphertext packet to reliable buffer */
                    struct buffer *in = reliable_get_buf(ks->rec_reliable);
                    ASSERT(in);
                    if (!buf_copy(in, buf))
                    {
                        msg(D_MULTI_DROPPED,
                            "Incoming control channel packet too big, dropping.");
                        goto error;
                    }
                    reliable_mark_active_incoming(ks->rec_reliable, in, id, op);
                }

                /* Process outgoing acknowledgment for packet just received, even if it's a replay */
                reliable_ack_acknowledge_packet_id(ks->rec_ack, id);
            }
        }
    }
    /* Remember that we received a valid control channel packet */
    ks->peer_last_packet = now;

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


struct key_state *
tls_select_encryption_key(struct tls_multi *multi)
{
    struct key_state *ks_select = NULL;
    for (int i = 0; i < KEY_SCAN_SIZE; ++i)
    {
        struct key_state *ks = get_key_scan(multi, i);
        if (ks->state >= S_GENERATED_KEYS && ks->authenticated == KS_AUTH_TRUE)
        {
            ASSERT(ks->crypto_options.key_ctx_bi.initialized);

            if (!ks_select)
            {
                ks_select = ks;
            }
            if (now >= ks->auth_deferred_expire)
            {
                ks_select = ks;
                break;
            }
        }
    }
    return ks_select;
}


/* Choose the key with which to encrypt a data packet */
void
tls_pre_encrypt(struct tls_multi *multi,
                struct buffer *buf, struct crypto_options **opt)
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
    uint8_t op;

    msg(D_TLS_DEBUG, __func__);

    ASSERT(ks);

    op = (P_DATA_V1 << P_OPCODE_SHIFT) | ks->key_id;
    ASSERT(buf_write_prepend(buf, &op, 1));
}

void
tls_prepend_opcode_v2(const struct tls_multi *multi, struct buffer *buf)
{
    struct key_state *ks = multi->save_ks;
    uint32_t peer;

    msg(D_TLS_DEBUG, __func__);

    ASSERT(ks);

    peer = htonl(((P_DATA_V2 << P_OPCODE_SHIFT) | ks->key_id) << 24
                 | (multi->peer_id & 0xFFFFFF));
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
tls_send_payload(struct key_state *ks,
                 const uint8_t *data,
                 int size)
{
    bool ret = false;

    tls_clear_error();

    ASSERT(ks);

    if (ks->state >= S_ACTIVE)
    {
        if (key_state_write_plaintext_const(&ks->ks_ssl, data, size) == 1)
        {
            ret = true;
        }
    }
    else
    {
        if (!ks->paybuf)
        {
            ks->paybuf = buffer_list_new();
        }
        buffer_list_push_data(ks->paybuf, data, (size_t)size);
        ret = true;
    }


    tls_clear_error();

    return ret;
}

bool
tls_rec_payload(struct tls_multi *multi,
                struct buffer *buf)
{
    bool ret = false;

    tls_clear_error();

    ASSERT(multi);

    struct key_state *ks = get_key_scan(multi, 0);

    if (ks->state >= S_ACTIVE && BLEN(&ks->plaintext_read_buf))
    {
        if (buf_copy(buf, &ks->plaintext_read_buf))
        {
            ret = true;
        }
        ks->plaintext_read_buf.len = 0;
    }

    tls_clear_error();

    return ret;
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
show_available_tls_ciphers(const char *cipher_list,
                           const char *cipher_list_tls13,
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
           "--tls-cipher and --show-tls for more details.\n\n"
           );
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
            buf_printf(&out, " tls_crypt_hmac=%s", format_hex(tls_crypt_hmac, TLS_CRYPT_TAG_SIZE, 0, gc));
        }
        /*
         * Remainder is encrypted and optional wKc
         */
        goto done;
    }

    /*
     * ACK list
     */
    buf_printf(&out, " %s", reliable_ack_print(&buf, (flags & PD_VERBOSE), gc));

    if (op == P_ACK_V1)
    {
        goto print_data;
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
