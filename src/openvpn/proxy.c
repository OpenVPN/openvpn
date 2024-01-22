/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
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
#endif

#include "syshead.h"

#include "common.h"
#include "misc.h"
#include "crypto.h"
#include "win32.h"
#include "socket.h"
#include "fdmisc.h"
#include "proxy.h"
#include "base64.h"
#include "httpdigest.h"
#include "ntlm.h"
#include "memdbg.h"
#include "forward.h"

#define UP_TYPE_PROXY        "HTTP Proxy"

struct http_proxy_options *
init_http_proxy_options_once(struct http_proxy_options **hpo,
                             struct gc_arena *gc)
{
    if (!*hpo)
    {
        ALLOC_OBJ_CLEAR_GC(*hpo, struct http_proxy_options, gc);
        /* http proxy defaults */
        (*hpo)->http_version = "1.0";
    }
    return *hpo;
}


/* cached proxy username/password */
static struct user_pass static_proxy_user_pass;

static bool
recv_line(socket_descriptor_t sd,
          char *buf,
          int len,
          const int timeout_sec,
          const bool verbose,
          struct buffer *lookahead,
          volatile int *signal_received)
{
    struct buffer la;
    int lastc = 0;

    CLEAR(la);
    if (lookahead)
    {
        la = *lookahead;
    }

    while (true)
    {
        int status;
        ssize_t size;
        fd_set reads;
        struct timeval tv;
        uint8_t c;

        if (buf_defined(&la))
        {
            ASSERT(buf_init(&la, 0));
        }

        FD_ZERO(&reads);
        openvpn_fd_set(sd, &reads);
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;

        status = select(sd + 1, &reads, NULL, NULL, &tv);

        get_signal(signal_received);
        if (*signal_received)
        {
            goto error;
        }

        /* timeout? */
        if (status == 0)
        {
            if (verbose)
            {
                msg(D_LINK_ERRORS | M_ERRNO, "recv_line: TCP port read timeout expired");
            }
            goto error;
        }

        /* error */
        if (status < 0)
        {
            if (verbose)
            {
                msg(D_LINK_ERRORS | M_ERRNO, "recv_line: TCP port read failed on select()");
            }
            goto error;
        }

        /* read single char */
        size = recv(sd, (void *)&c, 1, MSG_NOSIGNAL);

        /* error? */
        if (size != 1)
        {
            if (verbose)
            {
                msg(D_LINK_ERRORS | M_ERRNO, "recv_line: TCP port read failed on recv()");
            }
            goto error;
        }

#if 0
        if (isprint(c))
        {
            msg(M_INFO, "PROXY: read '%c' (%d)", c, (int)c);
        }
        else
        {
            msg(M_INFO, "PROXY: read (%d)", (int)c);
        }
#endif

        /* store char in buffer */
        if (len > 1)
        {
            *buf++ = c;
            --len;
        }

        /* also store char in lookahead buffer */
        if (buf_defined(&la))
        {
            buf_write_u8(&la, c);
            if (!isprint(c) && !isspace(c)) /* not ascii? */
            {
                if (verbose)
                {
                    msg(D_LINK_ERRORS | M_ERRNO, "recv_line: Non-ASCII character (%d) read on recv()", (int)c);
                }
                *lookahead = la;
                return false;
            }
        }

        /* end of line? */
        if (lastc == '\r' && c == '\n')
        {
            break;
        }

        lastc = c;
    }

    /* append trailing null */
    if (len > 0)
    {
        *buf++ = '\0';
    }

    return true;

error:
    return false;
}

static bool
send_line(socket_descriptor_t sd,
          const char *buf)
{
    const ssize_t size = send(sd, buf, strlen(buf), MSG_NOSIGNAL);
    if (size != (ssize_t) strlen(buf))
    {
        msg(D_LINK_ERRORS | M_ERRNO, "send_line: TCP port write failed on send()");
        return false;
    }
    return true;
}

static bool
send_line_crlf(socket_descriptor_t sd,
               const char *src)
{
    bool ret;

    struct buffer buf = alloc_buf(strlen(src) + 3);
    ASSERT(buf_write(&buf, src, strlen(src)));
    ASSERT(buf_write(&buf, "\r\n", 3));
    ret = send_line(sd, BSTR(&buf));
    free_buf(&buf);
    return ret;
}

static bool
send_crlf(socket_descriptor_t sd)
{
    return send_line_crlf(sd, "");
}

uint8_t *
make_base64_string2(const uint8_t *str, int src_len, struct gc_arena *gc)
{
    uint8_t *ret = NULL;
    char *b64out = NULL;
    ASSERT(openvpn_base64_encode((const void *)str, src_len, &b64out) >= 0);
    ret = (uint8_t *) string_alloc(b64out, gc);
    free(b64out);
    return ret;
}

uint8_t *
make_base64_string(const uint8_t *str, struct gc_arena *gc)
{
    return make_base64_string2(str, strlen((const char *)str), gc);
}

static const char *
username_password_as_base64(const struct http_proxy_info *p,
                            struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(strlen(p->up.username) + strlen(p->up.password) + 2, gc);
    ASSERT(strlen(p->up.username) > 0);
    buf_printf(&out, "%s:%s", p->up.username, p->up.password);
    return (const char *)make_base64_string((const uint8_t *)BSTR(&out), gc);
}

static void
clear_user_pass_http(void)
{
    purge_user_pass(&static_proxy_user_pass, true);
}

static void
get_user_pass_http(struct http_proxy_info *p, const bool force)
{
    /*
     * in case of forced (re)load, make sure the static storage is set as
     * undefined, otherwise get_user_pass() won't try to load any credential
     */
    if (force)
    {
        clear_user_pass_http();
    }

    if (!static_proxy_user_pass.defined)
    {
        unsigned int flags = GET_USER_PASS_MANAGEMENT;
        const char *auth_file = p->options.auth_file;
        if (p->options.auth_file_up)
        {
            auth_file = p->options.auth_file_up;
        }
        if (p->queried_creds)
        {
            flags |= GET_USER_PASS_PREVIOUS_CREDS_FAILED;
        }
        if (p->options.inline_creds)
        {
            flags |= GET_USER_PASS_INLINE_CREDS;
        }
        get_user_pass(&static_proxy_user_pass,
                      auth_file,
                      UP_TYPE_PROXY,
                      flags);
        p->queried_creds = true;
        p->up = static_proxy_user_pass;
    }
}

#if 0
/* function only used in #if 0 debug statement */
static void
dump_residual(socket_descriptor_t sd,
              int timeout,
              volatile int *signal_received)
{
    char buf[256];
    while (true)
    {
        if (!recv_line(sd, buf, sizeof(buf), timeout, true, NULL, signal_received))
        {
            return;
        }
        chomp(buf);
        msg(D_PROXY, "PROXY HEADER: '%s'", buf);
    }
}
#endif

/*
 * Extract the Proxy-Authenticate header from the stream.
 * Consumes all headers.
 */
static int
get_proxy_authenticate(socket_descriptor_t sd,
                       int timeout,
                       char **data,
                       volatile int *signal_received)
{
    char buf[256];
    int ret = HTTP_AUTH_NONE;
    while (true)
    {
        if (!recv_line(sd, buf, sizeof(buf), timeout, true, NULL, signal_received))
        {
            free(*data);
            *data = NULL;
            return HTTP_AUTH_NONE;
        }
        chomp(buf);
        if (!strlen(buf))
        {
            return ret;
        }
        if (ret == HTTP_AUTH_NONE && !strncmp(buf, "Proxy-Authenticate: ", 20))
        {
            if (!strncmp(buf+20, "Basic ", 6))
            {
                msg(D_PROXY, "PROXY AUTH BASIC: '%s'", buf);
                *data = string_alloc(buf+26, NULL);
                ret = HTTP_AUTH_BASIC;
            }
#if PROXY_DIGEST_AUTH
            else if (!strncmp(buf+20, "Digest ", 7))
            {
                msg(D_PROXY, "PROXY AUTH DIGEST: '%s'", buf);
                *data = string_alloc(buf+27, NULL);
                ret = HTTP_AUTH_DIGEST;
            }
#endif
#if NTLM
            else if (!strncmp(buf+20, "NTLM", 4))
            {
                msg(D_PROXY, "PROXY AUTH NTLM: '%s'", buf);
                *data = NULL;
                ret = HTTP_AUTH_NTLM;
            }
#endif
        }
    }
}

static void
store_proxy_authenticate(struct http_proxy_info *p, char *data)
{
    free(p->proxy_authenticate);
    p->proxy_authenticate = data;
}

/*
 * Parse out key/value pairs from Proxy-Authenticate string.
 * Return true on success, or false on parse failure.
 */
static bool
get_key_value(const char *str,       /* source string */
              char *key,             /* key stored here */
              char *value,           /* value stored here */
              int max_key_len,
              int max_value_len,
              const char **endptr)   /* next search position */
{
    int c;
    bool starts_with_quote = false;
    bool escape = false;

    for (c = max_key_len-1; (*str && (*str != '=') && c--); )
    {
        *key++ = *str++;
    }
    *key = '\0';

    if ('=' != *str++)
    {
        /* no key/value found */
        return false;
    }

    if ('\"' == *str)
    {
        /* quoted string */
        str++;
        starts_with_quote = true;
    }

    for (c = max_value_len-1; *str && c--; str++)
    {
        switch (*str)
        {
            case '\\':
                if (!escape)
                {
                    /* possibly the start of an escaped quote */
                    escape = true;
                    *value++ = '\\'; /* even though this is an escape character, we still
                                      * store it as-is in the target buffer */
                    continue;
                }
                break;

            case ',':
                if (!starts_with_quote)
                {
                    /* this signals the end of the value if we didn't get a starting quote
                     * and then we do "sloppy" parsing */
                    c = 0; /* the end */
                    continue;
                }
                break;

            case '\r':
            case '\n':
                /* end of string */
                c = 0;
                continue;

            case '\"':
                if (!escape && starts_with_quote)
                {
                    /* end of string */
                    c = 0;
                    continue;
                }
                break;
        }
        escape = false;
        *value++ = *str;
    }
    *value = '\0';

    *endptr = str;

    return true; /* success */
}

static char *
get_pa_var(const char *key, const char *pa, struct gc_arena *gc)
{
    char k[64];
    char v[256];
    const char *content = pa;

    while (true)
    {
        const int status = get_key_value(content, k, v, sizeof(k), sizeof(v), &content);
        if (status)
        {
            if (!strcmp(key, k))
            {
                return string_alloc(v, gc);
            }
        }
        else
        {
            return NULL;
        }

        /* advance to start of next key */
        if (*content == ',')
        {
            ++content;
        }
        while (*content && isspace(*content))
        {
            ++content;
        }
    }
}

struct http_proxy_info *
http_proxy_new(const struct http_proxy_options *o)
{
    struct http_proxy_info *p;

    if (!o || !o->server)
    {
        msg(M_FATAL, "HTTP_PROXY: server not specified");
    }

    ASSERT( o->port);

    ALLOC_OBJ_CLEAR(p, struct http_proxy_info);
    p->options = *o;

    /* parse authentication method */
    p->auth_method = HTTP_AUTH_NONE;
    if (o->auth_method_string)
    {
        if (!strcmp(o->auth_method_string, "none"))
        {
            p->auth_method = HTTP_AUTH_NONE;
        }
        else if (!strcmp(o->auth_method_string, "basic"))
        {
            p->auth_method = HTTP_AUTH_BASIC;
        }
#if NTLM
        else if (!strcmp(o->auth_method_string, "ntlm"))
        {
            msg(M_INFO, "NTLM v1 authentication is deprecated and will be removed in "
                "OpenVPN 2.7");
            p->auth_method = HTTP_AUTH_NTLM;
        }
        else if (!strcmp(o->auth_method_string, "ntlm2"))
        {
            p->auth_method = HTTP_AUTH_NTLM2;
        }
#endif
        else
        {
            msg(M_FATAL, "ERROR: unknown HTTP authentication method: '%s'",
                o->auth_method_string);
        }
    }

    /* only basic and NTLM/NTLMv2 authentication supported so far */
    if (p->auth_method == HTTP_AUTH_BASIC || p->auth_method == HTTP_AUTH_NTLM || p->auth_method == HTTP_AUTH_NTLM2)
    {
        get_user_pass_http(p, true);
    }

#if !NTLM
    if (p->auth_method == HTTP_AUTH_NTLM || p->auth_method == HTTP_AUTH_NTLM2)
    {
        msg(M_FATAL, "Sorry, this version of " PACKAGE_NAME " was built without NTLM Proxy support.");
    }
#endif

    p->defined = true;
    return p;
}

void
http_proxy_close(struct http_proxy_info *hp)
{
    free(hp);
}

static bool
add_proxy_headers(struct http_proxy_info *p,
                  socket_descriptor_t sd, /* already open to proxy */
                  const char *host,       /* openvpn server remote */
                  const char *port        /* openvpn server port */
                  )
{
    char buf[512];
    int i;
    bool host_header_sent = false;

    /*
     * Send custom headers if provided
     * If content is NULL the whole header is in name
     * Also remember if we already sent a Host: header
     */
    for  (i = 0; i < MAX_CUSTOM_HTTP_HEADER && p->options.custom_headers[i].name; i++)
    {
        if (p->options.custom_headers[i].content)
        {
            openvpn_snprintf(buf, sizeof(buf), "%s: %s",
                             p->options.custom_headers[i].name,
                             p->options.custom_headers[i].content);
            if (!strcasecmp(p->options.custom_headers[i].name, "Host"))
            {
                host_header_sent = true;
            }
        }
        else
        {
            openvpn_snprintf(buf, sizeof(buf), "%s",
                             p->options.custom_headers[i].name);
            if (!strncasecmp(p->options.custom_headers[i].name, "Host:", 5))
            {
                host_header_sent = true;
            }
        }

        msg(D_PROXY, "Send to HTTP proxy: '%s'", buf);
        if (!send_line_crlf(sd, buf))
        {
            return false;
        }
    }

    if (!host_header_sent)
    {
        openvpn_snprintf(buf, sizeof(buf), "Host: %s", host);
        msg(D_PROXY, "Send to HTTP proxy: '%s'", buf);
        if (!send_line_crlf(sd, buf))
        {
            return false;
        }
    }

    /* send User-Agent string if provided */
    if (p->options.user_agent)
    {
        openvpn_snprintf(buf, sizeof(buf), "User-Agent: %s",
                         p->options.user_agent);
        msg(D_PROXY, "Send to HTTP proxy: '%s'", buf);
        if (!send_line_crlf(sd, buf))
        {
            return false;
        }
    }

    return true;
}


bool
establish_http_proxy_passthru(struct http_proxy_info *p,
                              socket_descriptor_t sd,  /* already open to proxy */
                              const char *host,        /* openvpn server remote */
                              const char *port,          /* openvpn server port */
                              struct event_timeout *server_poll_timeout,
                              struct buffer *lookahead,
                              struct signal_info *sig_info)
{
    struct gc_arena gc = gc_new();
    char buf[512];
    char get[80];
    int status;
    int nparms;
    bool ret = false;
    bool processed = false;
    volatile int *signal_received = &sig_info->signal_received;

    /* get user/pass if not previously given */
    if (p->auth_method == HTTP_AUTH_BASIC
        || p->auth_method == HTTP_AUTH_DIGEST
        || p->auth_method == HTTP_AUTH_NTLM)
    {
        get_user_pass_http(p, false);
    }

    /* are we being called again after getting the digest server nonce in the previous transaction? */
    if (p->auth_method == HTTP_AUTH_DIGEST && p->proxy_authenticate)
    {
        nparms = 1;
        status = 407;
    }
    else
    {
        /* format HTTP CONNECT message */
        openvpn_snprintf(buf, sizeof(buf), "CONNECT %s:%s HTTP/%s",
                         host,
                         port,
                         p->options.http_version);

        msg(D_PROXY, "Send to HTTP proxy: '%s'", buf);

        /* send HTTP CONNECT message to proxy */
        if (!send_line_crlf(sd, buf))
        {
            goto error;
        }

        if (!add_proxy_headers(p, sd, host, port))
        {
            goto error;
        }

        /* auth specified? */
        switch (p->auth_method)
        {
            case HTTP_AUTH_NONE:
                break;

            case HTTP_AUTH_BASIC:
                openvpn_snprintf(buf, sizeof(buf), "Proxy-Authorization: Basic %s",
                                 username_password_as_base64(p, &gc));
                msg(D_PROXY, "Attempting Basic Proxy-Authorization");
                dmsg(D_SHOW_KEYS, "Send to HTTP proxy: '%s'", buf);
                if (!send_line_crlf(sd, buf))
                {
                    goto error;
                }
                break;

#if NTLM
            case HTTP_AUTH_NTLM:
            case HTTP_AUTH_NTLM2:
                /* keep-alive connection */
                openvpn_snprintf(buf, sizeof(buf), "Proxy-Connection: Keep-Alive");
                if (!send_line_crlf(sd, buf))
                {
                    goto error;
                }

                openvpn_snprintf(buf, sizeof(buf), "Proxy-Authorization: NTLM %s",
                                 ntlm_phase_1(p, &gc));
                msg(D_PROXY, "Attempting NTLM Proxy-Authorization phase 1");
                dmsg(D_SHOW_KEYS, "Send to HTTP proxy: '%s'", buf);
                if (!send_line_crlf(sd, buf))
                {
                    goto error;
                }
                break;
#endif

            default:
                ASSERT(0);
        }

        /* send empty CR, LF */
        if (!send_crlf(sd))
        {
            goto error;
        }

        /* receive reply from proxy */
        if (!recv_line(sd, buf, sizeof(buf), get_server_poll_remaining_time(server_poll_timeout), true, NULL, signal_received))
        {
            goto error;
        }

        /* remove trailing CR, LF */
        chomp(buf);

        msg(D_PROXY, "HTTP proxy returned: '%s'", buf);

        /* parse return string */
        nparms = sscanf(buf, "%*s %d", &status);

    }

    /* check for a "407 Proxy Authentication Required" response */
    while (nparms >= 1 && status == 407)
    {
        msg(D_PROXY, "Proxy requires authentication");

        if (p->auth_method == HTTP_AUTH_BASIC && !processed)
        {
            processed = true;
        }
        else if ((p->auth_method == HTTP_AUTH_NTLM || p->auth_method == HTTP_AUTH_NTLM2) && !processed) /* check for NTLM */
        {
#if NTLM
            /* look for the phase 2 response */
            char buf2[512];
            while (true)
            {
                if (!recv_line(sd, buf, sizeof(buf), get_server_poll_remaining_time(server_poll_timeout), true, NULL, signal_received))
                {
                    goto error;
                }
                chomp(buf);
                msg(D_PROXY, "HTTP proxy returned: '%s'", buf);

                CLEAR(buf2);
                openvpn_snprintf(get, sizeof(get), "%%*s NTLM %%%zus", sizeof(buf2) - 1);
                nparms = sscanf(buf, get, buf2);

                /* check for "Proxy-Authenticate: NTLM TlRM..." */
                if (nparms == 1)
                {
                    /* parse buf2 */
                    msg(D_PROXY, "auth string: '%s'", buf2);
                    break;
                }
            }
            /* if we are here then auth string was got */
            msg(D_PROXY, "Received NTLM Proxy-Authorization phase 2 response");

            /* receive and discard everything else */
            while (recv_line(sd, NULL, 0, 2, true, NULL, signal_received))
            {
            }

            /* now send the phase 3 reply */

            /* format HTTP CONNECT message */
            openvpn_snprintf(buf, sizeof(buf), "CONNECT %s:%s HTTP/%s",
                             host,
                             port,
                             p->options.http_version);

            msg(D_PROXY, "Send to HTTP proxy: '%s'", buf);

            /* send HTTP CONNECT message to proxy */
            if (!send_line_crlf(sd, buf))
            {
                goto error;
            }

            /* keep-alive connection */
            openvpn_snprintf(buf, sizeof(buf), "Proxy-Connection: Keep-Alive");
            if (!send_line_crlf(sd, buf))
            {
                goto error;
            }

            /* send HOST etc, */
            if (!add_proxy_headers(p, sd, host, port))
            {
                goto error;
            }

            msg(D_PROXY, "Attempting NTLM Proxy-Authorization phase 3");
            {
                const char *np3 = ntlm_phase_3(p, buf2, &gc);
                if (!np3)
                {
                    msg(D_PROXY, "NTLM Proxy-Authorization phase 3 failed: received corrupted data from proxy server");
                    goto error;
                }
                openvpn_snprintf(buf, sizeof(buf), "Proxy-Authorization: NTLM %s", np3);
            }

            msg(D_PROXY, "Send to HTTP proxy: '%s'", buf);
            if (!send_line_crlf(sd, buf))
            {
                goto error;
            }
            /* ok so far... */
            /* send empty CR, LF */
            if (!send_crlf(sd))
            {
                goto error;
            }

            /* receive reply from proxy */
            if (!recv_line(sd, buf, sizeof(buf), get_server_poll_remaining_time(server_poll_timeout), true, NULL, signal_received))
            {
                goto error;
            }

            /* remove trailing CR, LF */
            chomp(buf);

            msg(D_PROXY, "HTTP proxy returned: '%s'", buf);

            /* parse return string */
            nparms = sscanf(buf, "%*s %d", &status);
            processed = true;
#endif /* if NTLM */
        }
#if PROXY_DIGEST_AUTH
        else if (p->auth_method == HTTP_AUTH_DIGEST && !processed)
        {
            char *pa = p->proxy_authenticate;
            const int method = p->auth_method;
            ASSERT(pa);

            if (method == HTTP_AUTH_DIGEST)
            {
                const char *http_method = "CONNECT";
                const char *nonce_count = "00000001";
                const char *qop = "auth";
                const char *username = p->up.username;
                const char *password = p->up.password;
                char *opaque_kv = "";
                char uri[128];
                uint8_t cnonce_raw[8];
                uint8_t *cnonce;
                HASHHEX session_key;
                HASHHEX response;

                const char *realm = get_pa_var("realm", pa, &gc);
                const char *nonce = get_pa_var("nonce", pa, &gc);
                const char *algor = get_pa_var("algorithm", pa, &gc);
                const char *opaque = get_pa_var("opaque", pa, &gc);

                if (!realm || !nonce)
                {
                    msg(D_LINK_ERRORS, "HTTP proxy: digest auth failed, malformed response "
                        "from server: realm= or nonce= missing" );
                    goto error;
                }

                /* generate a client nonce */
                ASSERT(rand_bytes(cnonce_raw, sizeof(cnonce_raw)));
                cnonce = make_base64_string2(cnonce_raw, sizeof(cnonce_raw), &gc);


                /* build the digest response */
                openvpn_snprintf(uri, sizeof(uri), "%s:%s",
                                 host,
                                 port);

                if (opaque)
                {
                    const int len = strlen(opaque)+16;
                    opaque_kv = gc_malloc(len, false, &gc);
                    openvpn_snprintf(opaque_kv, len, ", opaque=\"%s\"", opaque);
                }

                DigestCalcHA1(algor,
                              username,
                              realm,
                              password,
                              nonce,
                              (char *)cnonce,
                              session_key);
                DigestCalcResponse(session_key,
                                   nonce,
                                   nonce_count,
                                   (char *)cnonce,
                                   qop,
                                   http_method,
                                   uri,
                                   NULL,
                                   response);

                /* format HTTP CONNECT message */
                openvpn_snprintf(buf, sizeof(buf), "%s %s HTTP/%s",
                                 http_method,
                                 uri,
                                 p->options.http_version);

                msg(D_PROXY, "Send to HTTP proxy: '%s'", buf);

                /* send HTTP CONNECT message to proxy */
                if (!send_line_crlf(sd, buf))
                {
                    goto error;
                }

                /* send HOST etc, */
                if (!add_proxy_headers(p, sd, host, port))
                {
                    goto error;
                }

                /* send digest response */
                openvpn_snprintf(buf, sizeof(buf), "Proxy-Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", qop=%s, nc=%s, cnonce=\"%s\", response=\"%s\"%s",
                                 username,
                                 realm,
                                 nonce,
                                 uri,
                                 qop,
                                 nonce_count,
                                 cnonce,
                                 response,
                                 opaque_kv
                                 );
                msg(D_PROXY, "Send to HTTP proxy: '%s'", buf);
                if (!send_line_crlf(sd, buf))
                {
                    goto error;
                }
                if (!send_crlf(sd))
                {
                    goto error;
                }

                /* receive reply from proxy */
                if (!recv_line(sd, buf, sizeof(buf), get_server_poll_remaining_time(server_poll_timeout), true, NULL, signal_received))
                {
                    goto error;
                }

                /* remove trailing CR, LF */
                chomp(buf);

                msg(D_PROXY, "HTTP proxy returned: '%s'", buf);

                /* parse return string */
                nparms = sscanf(buf, "%*s %d", &status);
                processed = true;
            }
            else
            {
                msg(D_PROXY, "HTTP proxy: digest method not supported");
                goto error;
            }
        }
#endif /* if PROXY_DIGEST_AUTH */
        else if (p->options.auth_retry)
        {
            /* figure out what kind of authentication the proxy needs */
            char *pa = NULL;
            const int method = get_proxy_authenticate(sd,
                                                      get_server_poll_remaining_time(server_poll_timeout),
                                                      &pa,
                                                      signal_received);
            if (method != HTTP_AUTH_NONE)
            {
                if (pa)
                {
                    msg(D_PROXY, "HTTP proxy authenticate '%s'", pa);
                }
                if (p->options.auth_retry == PAR_NCT && method == HTTP_AUTH_BASIC)
                {
                    msg(D_PROXY, "HTTP proxy: support for basic auth and other cleartext proxy auth methods is disabled");
                    free(pa);
                    goto error;
                }
                p->auth_method = method;
                store_proxy_authenticate(p, pa);
                ret = true;
                goto done;
            }
            else
            {
                msg(D_PROXY, "HTTP proxy: do not recognize the authentication method required by proxy");
                free(pa);
                goto error;
            }
        }
        else
        {
            if (!processed)
            {
                msg(D_PROXY, "HTTP proxy: no support for proxy authentication method");
            }
            goto error;
        }

        /* clear state */
        if (p->options.auth_retry)
        {
            clear_user_pass_http();
        }
        store_proxy_authenticate(p, NULL);
    }

    /* check return code, success = 200 */
    if (nparms < 1 || status != 200)
    {
        msg(D_LINK_ERRORS, "HTTP proxy returned bad status");
#if 0
        /* DEBUGGING -- show a multi-line HTTP error response */
        dump_residual(sd, get_server_poll_remaining_time(server_poll_timeout), signal_received);
#endif
        goto error;
    }

    /* SUCCESS */

    /* receive line from proxy and discard */
    if (!recv_line(sd, NULL, 0, get_server_poll_remaining_time(server_poll_timeout), true, NULL, signal_received))
    {
        goto error;
    }

    /*
     * Toss out any extraneous chars, but don't throw away the
     * start of the OpenVPN data stream (put it in lookahead).
     */
    while (recv_line(sd, NULL, 0, 2, false, lookahead, signal_received))
    {
    }

    /* reset queried_creds so that we don't think that the next creds request is due to an auth error */
    p->queried_creds = false;

#if 0
    if (lookahead && BLEN(lookahead))
    {
        msg(M_INFO, "HTTP PROXY: lookahead: %s", format_hex(BPTR(lookahead), BLEN(lookahead), 0));
    }
#endif

done:
    gc_free(&gc);
    return ret;

error:
    register_signal(sig_info, SIGUSR1, "HTTP proxy error"); /* SOFT-SIGUSR1 -- HTTP proxy error */
    gc_free(&gc);
    return ret;
}
