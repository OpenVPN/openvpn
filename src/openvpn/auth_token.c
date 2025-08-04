#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "base64.h"
#include "buffer.h"
#include "crypto.h"
#include "openvpn.h"
#include "ssl_common.h"
#include "auth_token.h"
#include "push.h"
#include "integer.h"
#include "ssl.h"
#include "ssl_verify.h"
#include <inttypes.h>

const char *auth_token_pem_name = "OpenVPN auth-token server key";

#define AUTH_TOKEN_SESSION_ID_LEN 12
#define AUTH_TOKEN_SESSION_ID_BASE64_LEN (AUTH_TOKEN_SESSION_ID_LEN * 8 / 6)

#if AUTH_TOKEN_SESSION_ID_LEN % 3
#error AUTH_TOKEN_SESSION_ID_LEN needs to be multiple a 3
#endif

/* Size of the data of the token (not b64 encoded and without prefix) */
#define TOKEN_DATA_LEN (2 * sizeof(int64_t) + AUTH_TOKEN_SESSION_ID_LEN + 32)

static struct key_type
auth_token_kt(void)
{
    return create_kt("none", "SHA256", "auth-gen-token");
}

void
add_session_token_env(struct tls_session *session, struct tls_multi *multi,
                      const struct user_pass *up)
{
    if (!multi->opt.auth_token_generate)
    {
        return;
    }

    int auth_token_state_flags = session->key[KS_PRIMARY].auth_token_state_flags;

    const char *state;

    if (!is_auth_token(up->password))
    {
        state = "Initial";
    }
    else if (auth_token_state_flags & AUTH_TOKEN_HMAC_OK)
    {
        switch (auth_token_state_flags & (AUTH_TOKEN_VALID_EMPTYUSER|AUTH_TOKEN_EXPIRED))
        {
            case 0:
                state = "Authenticated";
                break;

            case AUTH_TOKEN_EXPIRED:
                state = "Expired";
                break;

            case AUTH_TOKEN_VALID_EMPTYUSER:
                state = "AuthenticatedEmptyUser";
                break;

            case AUTH_TOKEN_VALID_EMPTYUSER | AUTH_TOKEN_EXPIRED:
                state = "ExpiredEmptyUser";
                break;

            default:
                /* Silence compiler warning, all four possible combinations are covered */
                ASSERT(0);
        }
    }
    else
    {
        state = "Invalid";
    }

    setenv_str(session->opt->es, "session_state", state);

    /* We had a valid session id before */
    const char *session_id_source;
    if (auth_token_state_flags & AUTH_TOKEN_HMAC_OK
        && !(auth_token_state_flags & AUTH_TOKEN_EXPIRED))
    {
        session_id_source = up->password;
    }
    else
    {
        /*
         * No session before, generate a new session token for the new session
         */
        if (!multi->auth_token_initial)
        {
            generate_auth_token(up, multi);
        }
        session_id_source = multi->auth_token_initial;
    }
    /*
     * In the auth-token the auth token is already base64 encoded
     * and being a multiple of 4 ensure that it a multiple of bytes
     * in the encoding
     */

    char session_id[AUTH_TOKEN_SESSION_ID_LEN*2] = {0};
    memcpy(session_id, session_id_source + strlen(SESSION_ID_PREFIX),
           AUTH_TOKEN_SESSION_ID_LEN*8/6);

    setenv_str(session->opt->es, "session_id", session_id);
}

void
auth_token_write_server_key_file(const char *filename)
{
    write_pem_key_file(filename, auth_token_pem_name);
}

void
auth_token_init_secret(struct key_ctx *key_ctx, const char *key_file,
                       bool key_inline)
{
    struct key_type kt = auth_token_kt();

    struct buffer server_secret_key = alloc_buf(2048);

    bool key_loaded = false;
    if (key_file)
    {
        key_loaded = read_pem_key_file(&server_secret_key,
                                       auth_token_pem_name,
                                       key_file, key_inline);
    }
    else
    {
        key_loaded = generate_ephemeral_key(&server_secret_key,
                                            auth_token_pem_name);
    }

    if (!key_loaded)
    {
        msg(M_FATAL, "ERROR: Cannot load auth-token secret");
    }

    struct key key;

    if (!buf_read(&server_secret_key, &key, sizeof(key)))
    {
        msg(M_FATAL, "ERROR: not enough data in auth-token secret");
    }

    struct key_parameters key_params;
    key_parameters_from_key(&key_params, &key);
    init_key_ctx(key_ctx, &key_params, &kt, false, "auth-token secret");

    free_buf(&server_secret_key);
}

void
generate_auth_token(const struct user_pass *up, struct tls_multi *multi)
{
    struct gc_arena gc = gc_new();

    int64_t timestamp = htonll((uint64_t)now);
    int64_t initial_timestamp = timestamp;

    hmac_ctx_t *ctx = multi->opt.auth_token_key.hmac;
    ASSERT(hmac_ctx_size(ctx) == 256/8);

    uint8_t sessid[AUTH_TOKEN_SESSION_ID_LEN];

    if (multi->auth_token_initial)
    {
        /* Just enough space to fit 8 bytes+ 1 extra to decode a non-padded
         * base64 string (multiple of 3 bytes). 9 bytes => 12 bytes base64
         * bytes
         */
        char old_tstamp_decode[9];

        /* Make a copy of the string to not modify multi->auth_token_initial */
        char *initial_token_copy = string_alloc(multi->auth_token_initial, &gc);

        char *old_sessid = initial_token_copy + strlen(SESSION_ID_PREFIX);
        char *old_tstamp_initial = old_sessid + AUTH_TOKEN_SESSION_ID_LEN*8/6;

        /*
         * We null terminate the old token just after the session ID to let
         * our base64 decode function only decode the session ID
         */
        old_tstamp_initial[12] = '\0';
        ASSERT(openvpn_base64_decode(old_tstamp_initial, old_tstamp_decode, 9) == 9);

        memcpy(&initial_timestamp, &old_tstamp_decode, sizeof(initial_timestamp));

        old_tstamp_initial[0] = '\0';
        ASSERT(openvpn_base64_decode(old_sessid, sessid, AUTH_TOKEN_SESSION_ID_LEN) == AUTH_TOKEN_SESSION_ID_LEN);
    }
    else if (!rand_bytes(sessid, AUTH_TOKEN_SESSION_ID_LEN))
    {
        msg( M_FATAL, "Failed to get enough randomness for "
             "authentication token");
    }

    /* Calculate the HMAC */
    /* We enforce up->username to be \0 terminated in ssl.c.. Allowing username
     * with \0 in them is asking for troubles in so many ways anyway that we
     * ignore that corner case here
     */
    uint8_t hmac_output[256/8];

    hmac_ctx_reset(ctx);

    /*
     * If the token was only valid for the empty user, also generate
     * a new token with the empty username since we do not want to loose
     * the information that the username cannot be trusted
     */
    struct key_state *ks = &multi->session[TM_ACTIVE].key[KS_PRIMARY];
    if (ks->auth_token_state_flags & AUTH_TOKEN_VALID_EMPTYUSER)
    {
        hmac_ctx_update(ctx, (const uint8_t *) "", 0);
    }
    else
    {
        hmac_ctx_update(ctx, (uint8_t *) up->username, (int) strlen(up->username));
    }
    hmac_ctx_update(ctx, sessid, AUTH_TOKEN_SESSION_ID_LEN);
    hmac_ctx_update(ctx, (uint8_t *) &initial_timestamp, sizeof(initial_timestamp));
    hmac_ctx_update(ctx, (uint8_t *) &timestamp, sizeof(timestamp));
    hmac_ctx_final(ctx, hmac_output);

    /* Construct the unencoded session token */
    struct buffer token = alloc_buf_gc(
        2*sizeof(uint64_t) + AUTH_TOKEN_SESSION_ID_LEN + 256/8, &gc);

    ASSERT(buf_write(&token, sessid, sizeof(sessid)));
    ASSERT(buf_write(&token, &initial_timestamp, sizeof(initial_timestamp)));
    ASSERT(buf_write(&token, &timestamp, sizeof(timestamp)));
    ASSERT(buf_write(&token, hmac_output, sizeof(hmac_output)));

    char *b64output = NULL;
    openvpn_base64_encode(BPTR(&token), BLEN(&token), &b64output);

    struct buffer session_token = alloc_buf_gc(
        strlen(SESSION_ID_PREFIX) + strlen(b64output) + 1, &gc);

    ASSERT(buf_write(&session_token, SESSION_ID_PREFIX, strlen(SESSION_ID_PREFIX)));
    ASSERT(buf_write(&session_token, b64output, (int)strlen(b64output)));
    ASSERT(buf_write_u8(&session_token, 0));

    free(b64output);

    /* free the auth-token if defined, we will replace it with a new one */
    free(multi->auth_token);
    multi->auth_token = strdup((char *)BPTR(&session_token));

    dmsg(D_SHOW_KEYS, "Generated token for client: %s (%s)",
         multi->auth_token, up->username);

    if (!multi->auth_token_initial)
    {
        /*
         * Save the initial auth token to continue using the same session ID
         * and timestamp in updates
         */
        multi->auth_token_initial = strdup(multi->auth_token);
    }

    gc_free(&gc);
}


static bool
check_hmac_token(hmac_ctx_t *ctx, const uint8_t *b64decoded, const char *username)
{
    ASSERT(hmac_ctx_size(ctx) == 256/8);

    uint8_t hmac_output[256/8];

    hmac_ctx_reset(ctx);
    hmac_ctx_update(ctx, (uint8_t *) username, (int)strlen(username));
    hmac_ctx_update(ctx, b64decoded, TOKEN_DATA_LEN - 256/8);
    hmac_ctx_final(ctx, hmac_output);

    const uint8_t *hmac = b64decoded + TOKEN_DATA_LEN - 256/8;
    return memcmp_constant_time(&hmac_output, hmac, 32) == 0;
}

unsigned int
verify_auth_token(struct user_pass *up, struct tls_multi *multi,
                  struct tls_session *session)
{
    /*
     * Base64 is <= input and input is < USER_PASS_LEN, so using USER_PASS_LEN
     * is safe here but a bit overkill
     */
    ASSERT(up && !up->protected);
    uint8_t b64decoded[USER_PASS_LEN];
    int decoded_len = openvpn_base64_decode(up->password + strlen(SESSION_ID_PREFIX),
                                            b64decoded, USER_PASS_LEN);

    /*
     * Ensure that the decoded data is the size of the
     * timestamp + hmac + session id
     */
    if (decoded_len != TOKEN_DATA_LEN)
    {
        msg(M_WARN, "ERROR: --auth-token wrong size (%d!=%d)",
            decoded_len, (int) TOKEN_DATA_LEN);
        return 0;
    }

    unsigned int ret = 0;

    const uint8_t *sessid = b64decoded;
    const uint8_t *tstamp_initial = sessid + AUTH_TOKEN_SESSION_ID_LEN;
    const uint8_t *tstamp = tstamp_initial + sizeof(int64_t);

    /* tstamp, tstamp_initial might not be aligned to an uint64, use memcpy
     * to avoid unaligned access */
    uint64_t timestamp = 0, timestamp_initial = 0;
    memcpy(&timestamp, tstamp, sizeof(uint64_t));
    timestamp = ntohll(timestamp);

    memcpy(&timestamp_initial, tstamp_initial, sizeof(uint64_t));
    timestamp_initial = ntohll(timestamp_initial);

    hmac_ctx_t *ctx = multi->opt.auth_token_key.hmac;
    if (check_hmac_token(ctx, b64decoded, up->username))
    {
        ret |= AUTH_TOKEN_HMAC_OK;
    }
    else if (check_hmac_token(ctx, b64decoded, ""))
    {
        ret |= AUTH_TOKEN_HMAC_OK;
        ret |= AUTH_TOKEN_VALID_EMPTYUSER;
        /* overwrite the username of the client with the empty one */
        strcpy(up->username, "");
    }
    else
    {
        msg(M_WARN, "--auth-gen-token: HMAC on token from client failed (%s)",
            up->username);
        return 0;
    }

    /* Accept session tokens only if their timestamp is in the acceptable range
     * for renegotiations */
    bool in_renegotiation_time = now >= timestamp
                                 && now < timestamp + 2 * session->opt->auth_token_renewal;

    if (!in_renegotiation_time)
    {
        msg(M_WARN, "Timestamp (%" PRIu64 ") of auth-token is out of the renewal window",
            timestamp);
        ret |= AUTH_TOKEN_EXPIRED;
    }

    /* Sanity check the initial timestamp */
    if (timestamp < timestamp_initial)
    {
        msg(M_WARN, "Initial timestamp (%" PRIu64 ") in token from client earlier than "
            "current timestamp %" PRIu64 ". Broken/unsynchronised clock?",
            timestamp_initial, timestamp);
        ret |= AUTH_TOKEN_EXPIRED;
    }

    if (multi->opt.auth_token_lifetime
        && now > timestamp_initial + multi->opt.auth_token_lifetime)
    {
        ret |= AUTH_TOKEN_EXPIRED;
    }

    if (ret & AUTH_TOKEN_EXPIRED)
    {
        /* Tell client that the session token is expired */
        auth_set_client_reason(multi, "SESSION: token expired");
        msg(M_INFO, "--auth-gen-token: auth-token from client expired");
    }

    /* Check that we do have the same session ID in the token as in our stored
     * auth-token to ensure that it did not change.
     * This also compares the prefix and session part of the
     * tokens, which should be identical if the session ID stayed the same */
    if (multi->auth_token_initial
        && memcmp_constant_time(multi->auth_token_initial, up->password,
                                strlen(SESSION_ID_PREFIX) + AUTH_TOKEN_SESSION_ID_BASE64_LEN))
    {
        msg(M_WARN, "--auth-gen-token: session id in token changed (Rejecting "
            "token.");
        ret = 0;
    }
    return ret;
}

void
wipe_auth_token(struct tls_multi *multi)
{
    if (multi)
    {
        if (multi->auth_token)
        {
            secure_memzero(multi->auth_token, strlen(multi->auth_token));
            free(multi->auth_token);
        }
        if (multi->auth_token_initial)
        {
            secure_memzero(multi->auth_token_initial,
                           strlen(multi->auth_token_initial));
            free(multi->auth_token_initial);
        }
        multi->auth_token = NULL;
        multi->auth_token_initial = NULL;
    }
}

void
check_send_auth_token(struct context *c)
{
    struct tls_multi *multi = c->c2.tls_multi;
    struct tls_session *session = &multi->session[TM_ACTIVE];

    if (get_primary_key(multi)->state < S_GENERATED_KEYS
        || get_primary_key(multi)->authenticated != KS_AUTH_TRUE)
    {
        /* the currently active session is still in renegotiation or another
         * not fully authorized state. We are either very close to a
         * renegotiation or have deauthorized the client. In both cases
         * we just ignore the request to send another token
         */
        return;
    }

    if (!multi->auth_token_initial)
    {
        msg(D_SHOW_KEYS, "initial auth-token not generated yet, skipping "
            "auth-token renewal.");
        return;
    }

    if (!multi->locked_username)
    {
        msg(D_SHOW_KEYS, "username not locked, skipping auth-token renewal.");
        return;
    }

    struct user_pass up;
    CLEAR(up);
    strncpynt(up.username, multi->locked_username, sizeof(up.username));

    generate_auth_token(&up, multi);

    resend_auth_token_renegotiation(multi, session);
}

void
resend_auth_token_renegotiation(struct tls_multi *multi, struct tls_session *session)
{
    /*
     * Auth token already sent to client, update auth-token on client.
     * The initial auth-token is sent as part of the push message, for this
     * update we need to schedule an extra push message.
     *
     * Otherwise, the auth-token get pushed out as part of the "normal"
     * push-reply
     */
    if (multi->auth_token_initial)
    {
        /*
         * We do not explicitly reschedule the sending of the
         * control message here. This might delay this reply
         * a few seconds but this message is not time critical
         */
        send_push_reply_auth_token(multi);
    }
}
