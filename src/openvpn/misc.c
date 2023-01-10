/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2014-2015 David Sommerseth <davids@redhat.com>
 *  Copyright (C) 2016-2023 David Sommerseth <davids@openvpn.net>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "buffer.h"
#include "misc.h"
#include "base64.h"
#include "tun.h"
#include "error.h"
#include "otime.h"
#include "plugin.h"
#include "options.h"
#include "manage.h"
#include "crypto.h"
#include "route.h"
#include "console.h"
#include "win32.h"

#include "memdbg.h"

#ifdef ENABLE_IPROUTE
const char *iproute_path = IPROUTE_PATH; /* GLOBAL */
#endif

/*
 * Set standard file descriptors to /dev/null
 */
void
set_std_files_to_null(bool stdin_only)
{
#if defined(HAVE_DUP) && defined(HAVE_DUP2)
    int fd;
    if ((fd = open("/dev/null", O_RDWR, 0)) != -1)
    {
        dup2(fd, 0);
        if (!stdin_only)
        {
            dup2(fd, 1);
            dup2(fd, 2);
        }
        if (fd > 2)
        {
            close(fd);
        }
    }
#endif
}

/*
 * Prepend a random string to hostname to prevent DNS caching.
 * For example, foo.bar.gov would be modified to <random-chars>.foo.bar.gov.
 * Of course, this requires explicit support in the DNS server (wildcard).
 */
const char *
hostname_randomize(const char *hostname, struct gc_arena *gc)
{
#define n_rnd_bytes 6

    uint8_t rnd_bytes[n_rnd_bytes];
    const char *rnd_str;
    struct buffer hname = alloc_buf_gc(strlen(hostname)+sizeof(rnd_bytes)*2+4, gc);

    prng_bytes(rnd_bytes, sizeof(rnd_bytes));
    rnd_str = format_hex_ex(rnd_bytes, sizeof(rnd_bytes), 40, 0, NULL, gc);
    buf_printf(&hname, "%s.%s", rnd_str, hostname);
    return BSTR(&hname);
#undef n_rnd_bytes
}

#ifdef ENABLE_MANAGEMENT
/* Get username/password from the management interface */
static bool
auth_user_pass_mgmt(struct user_pass *up, const char *prefix, const unsigned int flags,
                    const char *auth_challenge)
{
    const char *sc = NULL;

    if (flags & GET_USER_PASS_PREVIOUS_CREDS_FAILED)
    {
        management_auth_failure(management, prefix, "previous auth credentials failed");
    }

    if (auth_challenge && (flags & GET_USER_PASS_STATIC_CHALLENGE))
    {
        sc = auth_challenge;
    }
    if (!management_query_user_pass(management, up, prefix, flags, sc))
    {
        if ((flags & GET_USER_PASS_NOFATAL) != 0)
        {
            return false;
        }
        else
        {
            msg(M_FATAL, "ERROR: could not read %s username/password/ok/string from management interface", prefix);
        }
    }
    return true;
}
#endif /* ifdef ENABLE_MANAGEMENT */

/*
 * Get and store a username/password
 */

bool
get_user_pass_cr(struct user_pass *up,
                 const char *auth_file,
                 const char *prefix,
                 const unsigned int flags,
                 const char *auth_challenge)
{
    struct gc_arena gc = gc_new();

    if (!up->defined)
    {
        bool from_authfile = (auth_file && !streq(auth_file, "stdin"));
        bool username_from_stdin = false;
        bool password_from_stdin = false;
        bool response_from_stdin = true;

        if (flags & GET_USER_PASS_PREVIOUS_CREDS_FAILED)
        {
            msg(M_WARN, "Note: previous '%s' credentials failed", prefix);
        }

#ifdef ENABLE_MANAGEMENT
        /*
         * Get username/password from management interface?
         */
        if (management
            && (!from_authfile && (flags & GET_USER_PASS_MANAGEMENT))
            && management_query_user_pass_enabled(management))
        {
            response_from_stdin = false;
            if (!auth_user_pass_mgmt(up, prefix, flags, auth_challenge))
            {
                return false;
            }
        }
        else
#endif /* ifdef ENABLE_MANAGEMENT */
        /*
         * Get NEED_OK confirmation from the console
         */
        if (flags & GET_USER_PASS_NEED_OK)
        {
            struct buffer user_prompt = alloc_buf_gc(128, &gc);

            buf_printf(&user_prompt, "NEED-OK|%s|%s:", prefix, up->username);
            if (!query_user_SINGLE(BSTR(&user_prompt), BLEN(&user_prompt),
                                   up->password, USER_PASS_LEN, false))
            {
                msg(M_FATAL, "ERROR: could not read %s ok-confirmation from stdin", prefix);
            }

            if (!strlen(up->password))
            {
                strcpy(up->password, "ok");
            }
        }
        else if (flags & GET_USER_PASS_INLINE_CREDS)
        {
            struct buffer buf;
            buf_set_read(&buf, (uint8_t *) auth_file, strlen(auth_file) + 1);
            if (!(flags & GET_USER_PASS_PASSWORD_ONLY))
            {
                buf_parse(&buf, '\n', up->username, USER_PASS_LEN);
            }
            buf_parse(&buf, '\n', up->password, USER_PASS_LEN);

            if (strlen(up->password) == 0)
            {
                password_from_stdin = 1;
            }
        }
        /*
         * Read from auth file unless this is a dynamic challenge request.
         */
        else if (from_authfile && !(flags & GET_USER_PASS_DYNAMIC_CHALLENGE))
        {
            /*
             * Try to get username/password from a file.
             */
            FILE *fp;
            char password_buf[USER_PASS_LEN] = { '\0' };

            fp = platform_fopen(auth_file, "r");
            if (!fp)
            {
                msg(M_ERR, "Error opening '%s' auth file: %s", prefix, auth_file);
            }

            if ((flags & GET_USER_PASS_PASSWORD_ONLY) == 0)
            {
                /* Read username first */
                if (fgets(up->username, USER_PASS_LEN, fp) == NULL)
                {
                    msg(M_FATAL, "Error reading username from %s authfile: %s",
                        prefix,
                        auth_file);
                }
            }
            chomp(up->username);

            if (fgets(password_buf, USER_PASS_LEN, fp) != NULL)
            {
                chomp(password_buf);
            }

            if (flags & GET_USER_PASS_PASSWORD_ONLY && !password_buf[0])
            {
                msg(M_FATAL, "Error reading password from %s authfile: %s", prefix, auth_file);
            }

            if (password_buf[0])
            {
                strncpy(up->password, password_buf, USER_PASS_LEN);
            }
            /* The auth-file does not have the password: get both username
             * and password from the management interface if possible.
             * Otherwise set to read password from console.
             */
#if defined(ENABLE_MANAGEMENT)
            else if (management
                     && (flags & GET_USER_PASS_MANAGEMENT)
                     && management_query_user_pass_enabled(management))
            {
                msg(D_LOW, "No password found in %s authfile '%s'. Querying the management interface", prefix, auth_file);
                if (!auth_user_pass_mgmt(up, prefix, flags, auth_challenge))
                {
                    fclose(fp);
                    return false;
                }
            }
#endif
            else
            {
                password_from_stdin = 1;
            }

            fclose(fp);

            if (!(flags & GET_USER_PASS_PASSWORD_ONLY) && strlen(up->username) == 0)
            {
                msg(M_FATAL, "ERROR: username from %s authfile '%s' is empty", prefix, auth_file);
            }
        }
        else
        {
            username_from_stdin = true;
            password_from_stdin = true;
        }

        /*
         * Get username/password from standard input?
         */
        if (username_from_stdin || password_from_stdin || response_from_stdin)
        {
#ifdef ENABLE_MANAGEMENT
            if (auth_challenge && (flags & GET_USER_PASS_DYNAMIC_CHALLENGE) && response_from_stdin)
            {
                struct auth_challenge_info *ac = get_auth_challenge(auth_challenge, &gc);
                if (ac)
                {
                    char *response = (char *) gc_malloc(USER_PASS_LEN, false, &gc);
                    struct buffer packed_resp, challenge;

                    challenge = alloc_buf_gc(14+strlen(ac->challenge_text), &gc);
                    buf_printf(&challenge, "CHALLENGE: %s", ac->challenge_text);
                    buf_set_write(&packed_resp, (uint8_t *)up->password, USER_PASS_LEN);

                    if (!query_user_SINGLE(BSTR(&challenge), BLEN(&challenge),
                                           response, USER_PASS_LEN, BOOL_CAST(ac->flags&CR_ECHO)))
                    {
                        msg(M_FATAL, "ERROR: could not read challenge response from stdin");
                    }
                    strncpynt(up->username, ac->user, USER_PASS_LEN);
                    buf_printf(&packed_resp, "CRV1::%s::%s", ac->state_id, response);
                }
                else
                {
                    msg(M_FATAL, "ERROR: received malformed challenge request from server");
                }
            }
            else
#endif /* ifdef ENABLE_MANAGEMENT */
            {
                struct buffer user_prompt = alloc_buf_gc(128, &gc);
                struct buffer pass_prompt = alloc_buf_gc(128, &gc);

                query_user_clear();
                buf_printf(&user_prompt, "Enter %s Username:", prefix);
                buf_printf(&pass_prompt, "Enter %s Password:", prefix);

                if (username_from_stdin && !(flags & GET_USER_PASS_PASSWORD_ONLY))
                {
                    query_user_add(BSTR(&user_prompt), BLEN(&user_prompt),
                                   up->username, USER_PASS_LEN, true);
                }

                if (password_from_stdin)
                {
                    query_user_add(BSTR(&pass_prompt), BLEN(&pass_prompt),
                                   up->password, USER_PASS_LEN, false);
                }

                if (!query_user_exec() )
                {
                    msg(M_FATAL, "ERROR: Failed retrieving username or password");
                }

                if (!(flags & GET_USER_PASS_PASSWORD_ONLY))
                {
                    if (strlen(up->username) == 0)
                    {
                        msg(M_FATAL, "ERROR: %s username is empty", prefix);
                    }
                }

#ifdef ENABLE_MANAGEMENT
                if (auth_challenge && (flags & GET_USER_PASS_STATIC_CHALLENGE) && response_from_stdin)
                {
                    char *response = (char *) gc_malloc(USER_PASS_LEN, false, &gc);
                    struct buffer packed_resp, challenge;
                    char *pw64 = NULL, *resp64 = NULL;

                    challenge = alloc_buf_gc(14+strlen(auth_challenge), &gc);
                    buf_printf(&challenge, "CHALLENGE: %s", auth_challenge);

                    if (!query_user_SINGLE(BSTR(&challenge), BLEN(&challenge),
                                           response, USER_PASS_LEN,
                                           BOOL_CAST(flags & GET_USER_PASS_STATIC_CHALLENGE_ECHO)))
                    {
                        msg(M_FATAL, "ERROR: could not retrieve static challenge response");
                    }
                    if (openvpn_base64_encode(up->password, strlen(up->password), &pw64) == -1
                        || openvpn_base64_encode(response, strlen(response), &resp64) == -1)
                    {
                        msg(M_FATAL, "ERROR: could not base64-encode password/static_response");
                    }
                    buf_set_write(&packed_resp, (uint8_t *)up->password, USER_PASS_LEN);
                    buf_printf(&packed_resp, "SCRV1:%s:%s", pw64, resp64);
                    string_clear(pw64);
                    free(pw64);
                    string_clear(resp64);
                    free(resp64);
                }
#endif /* ifdef ENABLE_MANAGEMENT */
            }
        }

        string_mod(up->username, CC_PRINT, CC_CRLF, 0);
        string_mod(up->password, CC_PRINT, CC_CRLF, 0);

        up->defined = true;
    }

#if 0
    msg(M_INFO, "GET_USER_PASS %s u='%s' p='%s'", prefix, up->username, up->password);
#endif

    gc_free(&gc);

    return true;
}

#ifdef ENABLE_MANAGEMENT

/*
 * See management/management-notes.txt for more info on the
 * the dynamic challenge/response protocol implemented here.
 */
struct auth_challenge_info *
get_auth_challenge(const char *auth_challenge, struct gc_arena *gc)
{
    if (auth_challenge)
    {
        struct auth_challenge_info *ac;
        const int len = strlen(auth_challenge);
        char *work = (char *) gc_malloc(len+1, false, gc);
        char *cp;

        struct buffer b;
        buf_set_read(&b, (const uint8_t *)auth_challenge, len);

        ALLOC_OBJ_CLEAR_GC(ac, struct auth_challenge_info, gc);

        /* parse prefix */
        if (!buf_parse(&b, ':', work, len))
        {
            return NULL;
        }
        if (strcmp(work, "CRV1"))
        {
            return NULL;
        }

        /* parse flags */
        if (!buf_parse(&b, ':', work, len))
        {
            return NULL;
        }
        for (cp = work; *cp != '\0'; ++cp)
        {
            const char c = *cp;
            if (c == 'E')
            {
                ac->flags |= CR_ECHO;
            }
            else if (c == 'R')
            {
                ac->flags |= CR_RESPONSE;
            }
        }

        /* parse state ID */
        if (!buf_parse(&b, ':', work, len))
        {
            return NULL;
        }
        ac->state_id = string_alloc(work, gc);

        /* parse user name */
        if (!buf_parse(&b, ':', work, len))
        {
            return NULL;
        }
        ac->user = (char *) gc_malloc(strlen(work)+1, true, gc);
        openvpn_base64_decode(work, (void *)ac->user, -1);

        /* parse challenge text */
        ac->challenge_text = string_alloc(BSTR(&b), gc);

        return ac;
    }
    else
    {
        return NULL;
    }
}

#endif /* ifdef ENABLE_MANAGEMENT */

void
purge_user_pass(struct user_pass *up, const bool force)
{
    const bool nocache = up->nocache;
    static bool warn_shown = false;
    if (nocache || force)
    {
        secure_memzero(up, sizeof(*up));
        up->nocache = nocache;
    }
    /*
     * don't show warning if the pass has been replaced by a token: this is an
     * artificial "auth-nocache"
     */
    else if (!warn_shown)
    {
        msg(M_WARN, "WARNING: this configuration may cache passwords in memory -- use the auth-nocache option to prevent this");
        warn_shown = true;
    }
}

void
set_auth_token(struct user_pass *up, struct user_pass *tk, const char *token)
{

    if (strlen(token))
    {
        strncpynt(tk->password, token, USER_PASS_LEN);
        tk->token_defined = true;

        /*
         * --auth-token has no username, so it needs the username
         * either already set or copied from up, or later set by
         * --auth-token-user
         * If already set, tk is fully defined.
         */
        if (strlen(tk->username))
        {
            tk->defined = true;
        }
    }
}

void
set_auth_token_user(struct user_pass *tk, const char *username)
{
    if (strlen(username))
    {
        /* Clear the username before decoding to ensure no old material is left
         * and also allow decoding to not use all space to ensure the last byte is
         * always 0 */
        CLEAR(tk->username);
        int len = openvpn_base64_decode(username, tk->username, USER_PASS_LEN - 1);
        tk->defined = len > 0;
        if (!tk->defined)
        {
            msg(D_PUSH, "Error decoding auth-token-username");
        }
    }
}


/*
 * Process string received by untrusted peer before
 * printing to console or log file.
 *
 * Assumes that string has been null terminated.
 */
const char *
safe_print(const char *str, struct gc_arena *gc)
{
    return string_mod_const(str, CC_PRINT, CC_CRLF, '.', gc);
}

const char **
make_arg_array(const char *first, const char *parms, struct gc_arena *gc)
{
    char **ret = NULL;
    int base = 0;
    const int max_parms = MAX_PARMS + 2;
    int n = 0;

    /* alloc return array */
    ALLOC_ARRAY_CLEAR_GC(ret, char *, max_parms, gc);

    /* process first parameter, if provided */
    if (first)
    {
        ret[base++] = string_alloc(first, gc);
    }

    if (parms)
    {
        n = parse_line(parms, &ret[base], max_parms - base - 1, "make_arg_array", 0, M_WARN, gc);
        ASSERT(n >= 0 && n + base + 1 <= max_parms);
    }
    ret[base + n] = NULL;

    return (const char **)ret;
}

static const char **
make_inline_array(const char *str, struct gc_arena *gc)
{
    char line[OPTION_LINE_SIZE];
    struct buffer buf;
    int len = 0;
    char **ret = NULL;
    int i = 0;

    buf_set_read(&buf, (const uint8_t *) str, strlen(str));
    while (buf_parse(&buf, '\n', line, sizeof(line)))
    {
        ++len;
    }

    /* alloc return array */
    ALLOC_ARRAY_CLEAR_GC(ret, char *, len + 1, gc);

    buf_set_read(&buf, (const uint8_t *) str, strlen(str));
    while (buf_parse(&buf, '\n', line, sizeof(line)))
    {
        chomp(line);
        ASSERT(i < len);
        ret[i] = string_alloc(skip_leading_whitespace(line), gc);
        ++i;
    }
    ASSERT(i <= len);
    ret[i] = NULL;
    return (const char **)ret;
}

static const char **
make_arg_copy(char **p, struct gc_arena *gc)
{
    char **ret = NULL;
    const int len = string_array_len((const char **)p);
    const int max_parms = len + 1;
    int i;

    /* alloc return array */
    ALLOC_ARRAY_CLEAR_GC(ret, char *, max_parms, gc);

    for (i = 0; i < len; ++i)
    {
        ret[i] = p[i];
    }

    return (const char **)ret;
}

const char **
make_extended_arg_array(char **p, bool is_inline, struct gc_arena *gc)
{
    const int argc = string_array_len((const char **)p);
    if (is_inline)
    {
        return make_inline_array(p[0], gc);
    }
    else if (argc == 0)
    {
        return make_arg_array(NULL, NULL, gc);
    }
    else if (argc == 1)
    {
        return make_arg_array(p[0], NULL, gc);
    }
    else if (argc == 2)
    {
        return make_arg_array(p[0], p[1], gc);
    }
    else
    {
        return make_arg_copy(p, gc);
    }
}

/*
 * Remove security-sensitive strings from control message
 * so that they will not be output to log file.
 */
const char *
sanitize_control_message(const char *src, struct gc_arena *gc)
{
    char *ret = gc_malloc(strlen(src)+1, false, gc);
    char *dest = ret;
    bool redact = false;
    int skip = 0;

    for (;; )
    {
        const char c = *src;
        if (c == '\0')
        {
            break;
        }
        if (c == 'S' && !strncmp(src, "SESS_ID_", 8))
        {
            skip = 7;
            redact = true;
        }
        else if (c == 'e' && !strncmp(src, "echo ", 5))
        {
            skip = 4;
            redact = true;
        }
        else if (!check_debug_level(D_SHOW_KEYS)
                 && (c == 'a' && !strncmp(src, "auth-token ", 11)))
        {
            /* Unless --verb is 7 or higher (D_SHOW_KEYS), hide
             * the auth-token value coming in the src string
             */
            skip = 10;
            redact = true;
        }

        if (c == ',') /* end of redacted item? */
        {
            skip = 0;
            redact = false;
        }

        if (redact)
        {
            if (skip > 0)
            {
                --skip;
                *dest++ = c;
            }
        }
        else
        {
            *dest++ = c;
        }

        ++src;
    }
    *dest = '\0';
    return ret;
}

/* helper to parse peer_info received from multi client, validate
 * (this is untrusted data) and put into environment
 */
bool
validate_peer_info_line(char *line)
{
    uint8_t c;
    int state = 0;
    while (*line)
    {
        c = *line;
        switch (state)
        {
            case 0:
            case 1:
                if (c == '=' && state == 1)
                {
                    state = 2;
                }
                else if (isalnum(c) || c == '_')
                {
                    state = 1;
                }
                else
                {
                    return false;
                }

            case 2:
                /* after the '=', replace non-printable or shell meta with '_' */
                if (!isprint(c) || isspace(c)
                    || c == '$' || c == '(' || c == '`')
                {
                    *line = '_';
                }
        }
        line++;
    }
    return (state == 2);
}

void
output_peer_info_env(struct env_set *es, const char *peer_info)
{
    char line[256];
    struct buffer buf;
    buf_set_read(&buf, (const uint8_t *) peer_info, strlen(peer_info));
    while (buf_parse(&buf, '\n', line, sizeof(line)))
    {
        chomp(line);
        if (validate_peer_info_line(line)
            && (strncmp(line, "IV_", 3) == 0 || strncmp(line, "UV_", 3) == 0) )
        {
            msg(M_INFO, "peer info: %s", line);
            env_set_add(es, line);
        }
        else
        {
            msg(M_WARN, "validation failed on peer_info line received from client");
        }
    }
}

int
get_num_elements(const char *string, char delimiter)
{
    int string_len = strlen(string);

    ASSERT(0 != string_len);

    int element_count = 1;
    /* Get number of ciphers */
    for (int i = 0; i < string_len; i++)
    {
        if (string[i] == delimiter)
        {
            element_count++;
        }
    }

    return element_count;
}

struct buffer
prepend_dir(const char *dir, const char *path, struct gc_arena *gc)
{
    size_t len = strlen(dir) + strlen(PATH_SEPARATOR_STR) + strlen(path) + 1;
    struct buffer combined_path = alloc_buf_gc(len, gc);
    buf_printf(&combined_path, "%s%s%s", dir, PATH_SEPARATOR_STR, path);
    ASSERT(combined_path.len > 0);

    return combined_path;
}
