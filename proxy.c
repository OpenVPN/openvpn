/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

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

#ifdef WIN32
#include "ieproxy.h"
#endif

#include "memdbg.h"

#ifdef ENABLE_HTTP_PROXY

#define UP_TYPE_PROXY        "HTTP Proxy"

/* cached proxy username/password */
static struct user_pass static_proxy_user_pass;

static bool
recv_line (socket_descriptor_t sd,
	   char *buf,
	   int len,
	   const int timeout_sec,
	   const bool verbose,
	   struct buffer *lookahead,
	   volatile int *signal_received)
{
  struct buffer la;
  int lastc = 0;

  CLEAR (la);
  if (lookahead)
    la = *lookahead;

  while (true)
    {
      int status;
      ssize_t size;
      fd_set reads;
      struct timeval tv;
      uint8_t c;

      if (buf_defined (&la))
	{
	  ASSERT (buf_init (&la, 0));
	}

      FD_ZERO (&reads);
      FD_SET (sd, &reads);
      tv.tv_sec = timeout_sec;
      tv.tv_usec = 0;

      status = select (sd + 1, &reads, NULL, NULL, &tv);

      get_signal (signal_received);
      if (*signal_received)
	goto error;

      /* timeout? */
      if (status == 0)
	{
	  if (verbose)
	    msg (D_LINK_ERRORS | M_ERRNO_SOCK, "recv_line: TCP port read timeout expired");
	  goto error;
	}

      /* error */
      if (status < 0)
	{
	  if (verbose)
	    msg (D_LINK_ERRORS | M_ERRNO_SOCK, "recv_line: TCP port read failed on select()");
	  goto error;
	}

      /* read single char */
      size = recv (sd, &c, 1, MSG_NOSIGNAL);

      /* error? */
      if (size != 1)
	{
	  if (verbose)
	    msg (D_LINK_ERRORS | M_ERRNO_SOCK, "recv_line: TCP port read failed on recv()");
	  goto error;
	}

#if 0
      if (isprint(c))
	msg (M_INFO, "PROXY: read '%c' (%d)", c, (int)c);
      else
	msg (M_INFO, "PROXY: read (%d)", (int)c);
#endif

      /* store char in buffer */
      if (len > 1)
	{
	  *buf++ = c;
	  --len;
	}

      /* also store char in lookahead buffer */
      if (buf_defined (&la))
	{
	  buf_write_u8 (&la, c);
	  if (!isprint(c) && !isspace(c)) /* not ascii? */
	    {
	      if (verbose)
		msg (D_LINK_ERRORS | M_ERRNO_SOCK, "recv_line: Non-ASCII character (%d) read on recv()", (int)c);
	      *lookahead = la;
	      return false;
	    }
	}

      /* end of line? */
      if (lastc == '\r' && c == '\n')
	break;

      lastc = c;
    }

  /* append trailing null */
  if (len > 0)
    *buf++ = '\0';

  return true;

 error:
  return false;
}

static bool
send_line (socket_descriptor_t sd,
	   const char *buf)
{
  const ssize_t size = send (sd, buf, strlen (buf), MSG_NOSIGNAL);
  if (size != (ssize_t) strlen (buf))
    {
      msg (D_LINK_ERRORS | M_ERRNO_SOCK, "send_line: TCP port write failed on send()");
      return false;
    }
  return true;
}

static bool
send_line_crlf (socket_descriptor_t sd,
		const char *src)
{
  bool ret;

  struct buffer buf = alloc_buf (strlen (src) + 3);
  ASSERT (buf_write (&buf, src, strlen (src)));
  ASSERT (buf_write (&buf, "\r\n", 3));
  ret = send_line (sd, BSTR (&buf));
  free_buf (&buf);
  return ret;
}

static bool
send_crlf (socket_descriptor_t sd)
{
  return send_line_crlf (sd, "");
}

uint8_t *
make_base64_string2 (const uint8_t *str, int src_len, struct gc_arena *gc)
{
  uint8_t *ret = NULL;
  char *b64out = NULL;
  ASSERT (base64_encode ((const void *)str, src_len, &b64out) >= 0);
  ret = (uint8_t *) string_alloc (b64out, gc);
  free (b64out);
  return ret;
}

uint8_t *
make_base64_string (const uint8_t *str, struct gc_arena *gc)
{
  return make_base64_string2 (str, strlen ((const char *)str), gc);
}

static const char *
username_password_as_base64 (const struct http_proxy_info *p,
			     struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (strlen (p->up.username) + strlen (p->up.password) + 2, gc);
  ASSERT (strlen (p->up.username) > 0);
  buf_printf (&out, "%s:%s", p->up.username, p->up.password);
  return (const char *)make_base64_string ((const uint8_t*)BSTR (&out), gc);
}

static void
get_user_pass_http (struct http_proxy_info *p, const bool force)
{
  if (!static_proxy_user_pass.defined || force)
    {
      unsigned int flags = GET_USER_PASS_MANAGEMENT;
      if (p->queried_creds)
	flags |= GET_USER_PASS_PREVIOUS_CREDS_FAILED;
      get_user_pass (&static_proxy_user_pass,
		     p->options.auth_file,
		     UP_TYPE_PROXY,
		     flags);
      p->queried_creds = true;
      p->up = static_proxy_user_pass;
    }
}
static void
clear_user_pass_http (void)
{
  purge_user_pass (&static_proxy_user_pass, true);
}

static void
dump_residual (socket_descriptor_t sd,
	       int timeout,
	       volatile int *signal_received)
{
  char buf[256];
  while (true)
    {
      if (!recv_line (sd, buf, sizeof (buf), timeout, true, NULL, signal_received))
	return;
      chomp (buf);
      msg (D_PROXY, "PROXY HEADER: '%s'", buf);
    }
}

/*
 * Extract the Proxy-Authenticate header from the stream.
 * Consumes all headers.
 */
static int
get_proxy_authenticate (socket_descriptor_t sd,
		        int timeout,
			char **data,
			struct gc_arena *gc,
		        volatile int *signal_received)
{
  char buf[256];
  int ret = HTTP_AUTH_NONE;
  while (true)
    {
      if (!recv_line (sd, buf, sizeof (buf), timeout, true, NULL, signal_received))
	{
	  *data = NULL;
	  return HTTP_AUTH_NONE;
	}
      chomp (buf);
      if (!strlen(buf))
	return ret;
      if (ret == HTTP_AUTH_NONE && !strncmp(buf, "Proxy-Authenticate: ", 20))
	{
	  if (!strncmp(buf+20, "Basic ", 6))
	    {
	      msg (D_PROXY, "PROXY AUTH BASIC: '%s'", buf);
	      *data = string_alloc(buf+26, gc);
	      ret = HTTP_AUTH_BASIC;
	    }
#if PROXY_DIGEST_AUTH
	  else if (!strncmp(buf+20, "Digest ", 7))
	    {
	      msg (D_PROXY, "PROXY AUTH DIGEST: '%s'", buf);
	      *data = string_alloc(buf+27, gc);
	      ret = HTTP_AUTH_DIGEST;
	    }
#endif
#if NTLM
	  else if (!strncmp(buf+20, "NTLM", 4))
	    {
	      msg (D_PROXY, "PROXY AUTH HTLM: '%s'", buf);
	      *data = NULL;
	      ret = HTTP_AUTH_NTLM;
	    }
#endif
	}
    }
}

static void
store_proxy_authenticate (struct http_proxy_info *p, char *data)
{
  if (p->proxy_authenticate)
    free (p->proxy_authenticate);
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
    *key++ = *str++;
  *key = '\0';

  if('=' != *str++)
    /* no key/value found */
    return false;

  if('\"' == *str)
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
				  store it as-is in the target buffer */
	      continue;
	    }
	  break;
	case ',':
	  if (!starts_with_quote)
	    {
	      /* this signals the end of the value if we didn't get a starting quote
		 and then we do "sloppy" parsing */
	      c=0; /* the end */
	      continue;
	    }
	  break;
	case '\r':
	case '\n':
	  /* end of string */
	  c=0;
	continue;
	case '\"':
	  if (!escape && starts_with_quote)
	    {
	      /* end of string */
	      c=0;
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
get_pa_var (const char *key, const char *pa, struct gc_arena *gc)
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
	    return string_alloc(v, gc);
	}
      else
	return NULL;

      /* advance to start of next key */
      if (*content == ',')
	++content;
      while (*content && isspace(*content))
	++content;
    }
}

struct http_proxy_info *
http_proxy_new (const struct http_proxy_options *o,
		struct auto_proxy_info *auto_proxy_info)
{
  struct http_proxy_info *p;
  struct http_proxy_options opt;

  if (auto_proxy_info)
    {
      if (o && o->server)
	{
	  /* if --http-proxy explicitly given, disable auto-proxy */
	  auto_proxy_info = NULL;
	}
      else
	{
	  /* if no --http-proxy explicitly given and no auto settings, fail */
	  if (!auto_proxy_info->http.server)
	    return NULL;

	  if (o)
	    {
	      opt = *o;
	    }
	  else
	    {
	      CLEAR (opt);
	  
	      /* These settings are only used for --auto-proxy */
	      opt.timeout = 5;
	      opt.http_version = "1.0";
	    }

	  opt.server = auto_proxy_info->http.server;
	  opt.port = auto_proxy_info->http.port;
	  if (!opt.auth_retry)
	    opt.auth_retry = PAR_ALL;

	  o = &opt;
	}
    }

  if (!o || !o->server)
    msg (M_FATAL, "HTTP_PROXY: server not specified");

  ASSERT (legal_ipv4_port (o->port));

  ALLOC_OBJ_CLEAR (p, struct http_proxy_info);
  p->options = *o;

  /* parse authentication method */
  p->auth_method = HTTP_AUTH_NONE;
  if (o->auth_method_string)
    {
      if (!strcmp (o->auth_method_string, "none"))
	p->auth_method = HTTP_AUTH_NONE;
      else if (!strcmp (o->auth_method_string, "basic"))
	p->auth_method = HTTP_AUTH_BASIC;
#if NTLM
      else if (!strcmp (o->auth_method_string, "ntlm"))
	p->auth_method = HTTP_AUTH_NTLM;
      else if (!strcmp (o->auth_method_string, "ntlm2"))
	p->auth_method = HTTP_AUTH_NTLM2;
#endif
      else
	msg (M_FATAL, "ERROR: unknown HTTP authentication method: '%s'",
	     o->auth_method_string);
    }

  /* only basic and NTLM/NTLMv2 authentication supported so far */
  if (p->auth_method == HTTP_AUTH_BASIC || p->auth_method == HTTP_AUTH_NTLM || p->auth_method == HTTP_AUTH_NTLM2)
    {
      get_user_pass_http (p, true);
    }

#if !NTLM
  if (p->auth_method == HTTP_AUTH_NTLM || p->auth_method == HTTP_AUTH_NTLM2)
    msg (M_FATAL, "Sorry, this version of " PACKAGE_NAME " was built without NTLM Proxy support.");
#endif

  p->defined = true;
  return p;
}

void
http_proxy_close (struct http_proxy_info *hp)
{
  free (hp);
}

bool
establish_http_proxy_passthru (struct http_proxy_info *p,
			       socket_descriptor_t sd, /* already open to proxy */
			       const char *host,       /* openvpn server remote */
			       const int port,         /* openvpn server port */
			       struct buffer *lookahead,
			       volatile int *signal_received)
{
  struct gc_arena gc = gc_new ();
  char buf[512];
  char buf2[128];
  char get[80];
  int status;
  int nparms;
  bool ret = false;
  bool processed = false;

  /* get user/pass if not previously given or if --auto-proxy is being used */
  if (p->auth_method == HTTP_AUTH_BASIC
      || p->auth_method == HTTP_AUTH_DIGEST
      || p->auth_method == HTTP_AUTH_NTLM)
    get_user_pass_http (p, false);

  /* are we being called again after getting the digest server nonce in the previous transaction? */
  if (p->auth_method == HTTP_AUTH_DIGEST && p->proxy_authenticate)
    {
      nparms = 1;
      status = 407;
    }
  else
    {
      /* format HTTP CONNECT message */
      openvpn_snprintf (buf, sizeof(buf), "CONNECT %s:%d HTTP/%s",
			host,
			port,
			p->options.http_version);

      msg (D_PROXY, "Send to HTTP proxy: '%s'", buf);

      /* send HTTP CONNECT message to proxy */
      if (!send_line_crlf (sd, buf))
	goto error;

      openvpn_snprintf(buf, sizeof(buf), "Host: %s", host);
      if (!send_line_crlf(sd, buf))
        goto error;

      /* send User-Agent string if provided */
      if (p->options.user_agent)
	{
	  openvpn_snprintf (buf, sizeof(buf), "User-Agent: %s",
			    p->options.user_agent);
	  if (!send_line_crlf (sd, buf))
	    goto error;
	}

      /* auth specified? */
      switch (p->auth_method)
	{
	case HTTP_AUTH_NONE:
	  break;

	case HTTP_AUTH_BASIC:
	  openvpn_snprintf (buf, sizeof(buf), "Proxy-Authorization: Basic %s",
			    username_password_as_base64 (p, &gc));
	  msg (D_PROXY, "Attempting Basic Proxy-Authorization");
	  dmsg (D_SHOW_KEYS, "Send to HTTP proxy: '%s'", buf);
	  if (!send_line_crlf (sd, buf))
	    goto error;
	  break;

#if NTLM
	case HTTP_AUTH_NTLM:
	case HTTP_AUTH_NTLM2:
	  /* keep-alive connection */
	  openvpn_snprintf (buf, sizeof(buf), "Proxy-Connection: Keep-Alive");
	  if (!send_line_crlf (sd, buf))
	    goto error;

	  openvpn_snprintf (buf, sizeof(buf), "Proxy-Authorization: NTLM %s",
			    ntlm_phase_1 (p, &gc));
	  msg (D_PROXY, "Attempting NTLM Proxy-Authorization phase 1");
	  dmsg (D_SHOW_KEYS, "Send to HTTP proxy: '%s'", buf);
	  if (!send_line_crlf (sd, buf))
	    goto error;
	  break;
#endif

	default:
	  ASSERT (0);
	}

      /* send empty CR, LF */
      if (!send_crlf (sd))
	goto error;

      /* receive reply from proxy */
      if (!recv_line (sd, buf, sizeof(buf), p->options.timeout, true, NULL, signal_received))
	goto error;

      /* remove trailing CR, LF */
      chomp (buf);

      msg (D_PROXY, "HTTP proxy returned: '%s'", buf);

      /* parse return string */
      nparms = sscanf (buf, "%*s %d", &status);

    }

  /* check for a "407 Proxy Authentication Required" response */
  while (nparms >= 1 && status == 407)
    {
      msg (D_PROXY, "Proxy requires authentication");

      if (p->auth_method == HTTP_AUTH_BASIC && !processed)
	{
	  processed = true;
	}
      else if ((p->auth_method == HTTP_AUTH_NTLM || p->auth_method == HTTP_AUTH_NTLM2) && !processed) /* check for NTLM */
        {
#if NTLM
          /* look for the phase 2 response */

          while (true)
            {
              if (!recv_line (sd, buf, sizeof(buf), p->options.timeout, true, NULL, signal_received))
                goto error;
              chomp (buf);
              msg (D_PROXY, "HTTP proxy returned: '%s'", buf);

              openvpn_snprintf (get, sizeof get, "%%*s NTLM %%%ds", (int) sizeof (buf2) - 1);
              nparms = sscanf (buf, get, buf2);
              buf2[127] = 0; /* we only need the beginning - ensure it's null terminated. */

              /* check for "Proxy-Authenticate: NTLM TlRM..." */
              if (nparms == 1)
                {
                  /* parse buf2 */
                  msg (D_PROXY, "auth string: '%s'", buf2);
                  break;
                }
            }
          /* if we are here then auth string was got */
          msg (D_PROXY, "Received NTLM Proxy-Authorization phase 2 response");

          /* receive and discard everything else */
          while (recv_line (sd, NULL, 0, 2, true, NULL, signal_received))
            ;

          /* now send the phase 3 reply */

          /* format HTTP CONNECT message */
          openvpn_snprintf (buf, sizeof(buf), "CONNECT %s:%d HTTP/%s",
			    host,
			    port,
			    p->options.http_version);

          msg (D_PROXY, "Send to HTTP proxy: '%s'", buf);

          /* send HTTP CONNECT message to proxy */
          if (!send_line_crlf (sd, buf))
            goto error;

          /* keep-alive connection */
          openvpn_snprintf (buf, sizeof(buf), "Proxy-Connection: Keep-Alive");
          if (!send_line_crlf (sd, buf))
            goto error;

          
          /* send HOST etc, */
          openvpn_snprintf (buf, sizeof(buf), "Host: %s", host);
          msg (D_PROXY, "Send to HTTP proxy: '%s'", buf);
          if (!send_line_crlf (sd, buf))
            goto error;

          msg (D_PROXY, "Attempting NTLM Proxy-Authorization phase 3");
	  {
	    const char *np3 = ntlm_phase_3 (p, buf2, &gc);
	    if (!np3)
	      {
		msg (D_PROXY, "NTLM Proxy-Authorization phase 3 failed: received corrupted data from proxy server");
		goto error;
	      }
	    openvpn_snprintf (buf, sizeof(buf), "Proxy-Authorization: NTLM %s", np3);
	  }

          msg (D_PROXY, "Send to HTTP proxy: '%s'", buf);
          if (!send_line_crlf (sd, buf))
	    goto error;
          /* ok so far... */
          /* send empty CR, LF */
          if (!send_crlf (sd))
            goto error;

          /* receive reply from proxy */
          if (!recv_line (sd, buf, sizeof(buf), p->options.timeout, true, NULL, signal_received))
            goto error;

          /* remove trailing CR, LF */
          chomp (buf);

          msg (D_PROXY, "HTTP proxy returned: '%s'", buf);

          /* parse return string */
          nparms = sscanf (buf, "%*s %d", &status);
	  processed = true;
#endif
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

	      /* generate a client nonce */
	      ASSERT(RAND_bytes(cnonce_raw, sizeof(cnonce_raw)));
	      cnonce = make_base64_string2(cnonce_raw, sizeof(cnonce_raw), &gc);


	      /* build the digest response */
	      openvpn_snprintf (uri, sizeof(uri), "%s:%d",
				host,
				port);

	      if (opaque)
		{
		  const int len = strlen(opaque)+16;
		  opaque_kv = gc_malloc(len, false, &gc);
		  openvpn_snprintf (opaque_kv, len, ", opaque=\"%s\"", opaque);
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
	      openvpn_snprintf (buf, sizeof(buf), "%s %s HTTP/%s",
				http_method,
				uri,
				p->options.http_version);

	      msg (D_PROXY, "Send to HTTP proxy: '%s'", buf);

	      /* send HTTP CONNECT message to proxy */
	      if (!send_line_crlf (sd, buf))
		goto error;

	      /* send HOST etc, */
	      openvpn_snprintf (buf, sizeof(buf), "Host: %s", host);
	      msg (D_PROXY, "Send to HTTP proxy: '%s'", buf);
	      if (!send_line_crlf (sd, buf))
		goto error;

	      /* send digest response */
	      openvpn_snprintf (buf, sizeof(buf), "Proxy-Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", qop=%s, nc=%s, cnonce=\"%s\", response=\"%s\"%s",
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
	      msg (D_PROXY, "Send to HTTP proxy: '%s'", buf);
	      if (!send_line_crlf (sd, buf))
		goto error;
	      if (!send_crlf (sd))
		goto error;

	      /* receive reply from proxy */
	      if (!recv_line (sd, buf, sizeof(buf), p->options.timeout, true, NULL, signal_received))
		goto error;

	      /* remove trailing CR, LF */
	      chomp (buf);

	      msg (D_PROXY, "HTTP proxy returned: '%s'", buf);

	      /* parse return string */
	      nparms = sscanf (buf, "%*s %d", &status);
	      processed = true;
	    }
	  else
	    {
	      msg (D_PROXY, "HTTP proxy: digest method not supported");
	      goto error;
	    }
	}
#endif
      else if (p->options.auth_retry)
	{
	  /* figure out what kind of authentication the proxy needs */
	  char *pa = NULL;
	  const int method = get_proxy_authenticate(sd,
						    p->options.timeout,
						    &pa,
						    NULL,
						    signal_received);
	  if (method != HTTP_AUTH_NONE)
	    {
	      if (pa)
		msg (D_PROXY, "HTTP proxy authenticate '%s'", pa);
	      if (p->options.auth_retry == PAR_NCT && method == HTTP_AUTH_BASIC)
		{
		  msg (D_PROXY, "HTTP proxy: support for basic auth and other cleartext proxy auth methods is disabled");
		  goto error;
		}
	      p->auth_method = method;
	      store_proxy_authenticate(p, pa);
	      ret = true;
	      goto done;
	    }
	  else
	    {
	      msg (D_PROXY, "HTTP proxy: do not recognize the authentication method required by proxy");
	      free (pa);
	      goto error;
	    }
	}
      else
	{
	  if (!processed)
	    msg (D_PROXY, "HTTP proxy: no support for proxy authentication method");
	  goto error;
	}

      /* clear state */
      if (p->options.auth_retry)
	clear_user_pass_http();
      store_proxy_authenticate(p, NULL);
    }

  /* check return code, success = 200 */
  if (nparms < 1 || status != 200)
    {
      msg (D_LINK_ERRORS, "HTTP proxy returned bad status");
#if 0
      /* DEBUGGING -- show a multi-line HTTP error response */
      dump_residual(sd, p->options.timeout, signal_received);
#endif
      goto error;
    }

  /* SUCCESS */

  /* receive line from proxy and discard */
  if (!recv_line (sd, NULL, 0, p->options.timeout, true, NULL, signal_received))
    goto error;

  /*
   * Toss out any extraneous chars, but don't throw away the
   * start of the OpenVPN data stream (put it in lookahead).
   */
  while (recv_line (sd, NULL, 0, 2, false, lookahead, signal_received))
    ;

  /* reset queried_creds so that we don't think that the next creds request is due to an auth error */
  p->queried_creds = false;

#if 0
  if (lookahead && BLEN (lookahead))
    msg (M_INFO, "HTTP PROXY: lookahead: %s", format_hex (BPTR (lookahead), BLEN (lookahead), 0));
#endif

 done:
  gc_free (&gc);
  return ret;

 error:
  /* on error, should we exit or restart? */
  if (!*signal_received)
    *signal_received = (p->options.retry ? SIGUSR1 : SIGTERM); /* SOFT-SIGUSR1 -- HTTP proxy error */
  gc_free (&gc);
  return ret;
}

#else
static void dummy(void) {}
#endif /* ENABLE_HTTP_PROXY */

#ifdef GENERAL_PROXY_SUPPORT

#ifdef WIN32

#if 0
char *
get_windows_internet_string (const DWORD dwOption, struct gc_arena *gc)
{
  DWORD size = 0;
  char *ret = NULL;

  /* Initially, get size of return buffer */
  InternetQueryOption (NULL, dwOption, NULL, &size);
  if (size)
    {
      /* Now get actual info */
      ret = (INTERNET_PROXY_INFO *) gc_malloc (size, false, gc);
      if (!InternetQueryOption (NULL, dwOption, (LPVOID) ret, &size))
	ret = NULL;
    }
  return ret;
}
#endif

static INTERNET_PROXY_INFO *
get_windows_proxy_settings (struct gc_arena *gc)
{
  DWORD size = 0;
  INTERNET_PROXY_INFO *ret = NULL;

  /* Initially, get size of return buffer */
  InternetQueryOption (NULL, INTERNET_OPTION_PROXY, NULL, &size);
  if (size)
    {
      /* Now get actual info */
      ret = (INTERNET_PROXY_INFO *) gc_malloc (size, false, gc);
      if (!InternetQueryOption (NULL, INTERNET_OPTION_PROXY, (LPVOID) ret, &size))
	ret = NULL;
    }
  return ret;
}

static const char *
parse_windows_proxy_setting (const char *str, struct auto_proxy_info_entry *e, struct gc_arena *gc)
{
  char buf[128];
  const char *ret = NULL;
  struct buffer in;

  CLEAR (*e);

  buf_set_read (&in, (const uint8_t *)str, strlen (str));

  if (strchr (str, '=') != NULL)
    {
      if (buf_parse (&in, '=', buf, sizeof (buf)))
	ret = string_alloc (buf, gc);
    }
	
  if (buf_parse (&in, ':', buf, sizeof (buf)))
    e->server = string_alloc (buf, gc);

  if (e->server && buf_parse (&in, '\0', buf, sizeof (buf)))
    e->port = atoi (buf);

  return ret;
}

static void
parse_windows_proxy_setting_list (const char *str, const char *type, struct auto_proxy_info_entry *e, struct gc_arena *gc)
{
  struct gc_arena gc_local = gc_new ();
  struct auto_proxy_info_entry el;

  CLEAR (*e);
  if (type)
    {
      char buf[128];
      struct buffer in;

      buf_set_read (&in, (const uint8_t *)str, strlen (str));
      if (strchr (str, '=') != NULL)
	{
	  while (buf_parse (&in, ' ', buf, sizeof (buf)))
	    {
	      const char *t = parse_windows_proxy_setting (buf, &el, &gc_local);
	      if (t && !strcmp (t, type))
		goto found;
	    }
	}
    }
  else
    {
      if (!parse_windows_proxy_setting (str, &el, &gc_local))
	goto found;
    }
  goto done;

 found:
  if (el.server && el.port > 0)
    {
      e->server = string_alloc (el.server, gc);
      e->port = el.port;
    }

 done:
  gc_free (&gc_local);
}

static const char *
win_proxy_access_type (const DWORD dwAccessType)
{
  switch (dwAccessType)
    {
    case INTERNET_OPEN_TYPE_DIRECT:
      return "INTERNET_OPEN_TYPE_DIRECT";
    case INTERNET_OPEN_TYPE_PROXY:
      return "INTERNET_OPEN_TYPE_PROXY";
    default:
      return "[UNKNOWN]";
    }
}

void
show_win_proxy_settings (const int msglevel)
{
  INTERNET_PROXY_INFO *info;
  struct gc_arena gc = gc_new ();

  info = get_windows_proxy_settings (&gc);
  msg (msglevel, "PROXY INFO: %s %s",
       win_proxy_access_type (info->dwAccessType),
       info->lpszProxy ? info->lpszProxy : "[NULL]");

  gc_free (&gc);
}

struct auto_proxy_info *
get_proxy_settings (char **err, struct gc_arena *gc)
{
  struct gc_arena gc_local = gc_new ();
  INTERNET_PROXY_INFO *info;
  struct auto_proxy_info *pi;

  ALLOC_OBJ_CLEAR_GC (pi, struct auto_proxy_info, gc);

  if (err)
    *err = NULL;

  info = get_windows_proxy_settings (&gc_local);

  if (!info)
    {
      if (err)
	*err = "PROXY: failed to obtain windows proxy info";
      goto done;
    }

  switch (info->dwAccessType)
    {
    case INTERNET_OPEN_TYPE_DIRECT:
      break;
    case INTERNET_OPEN_TYPE_PROXY:
      if (!info->lpszProxy)
	break;
      parse_windows_proxy_setting_list (info->lpszProxy, NULL, &pi->http, gc);
      if (!pi->http.server)
	parse_windows_proxy_setting_list (info->lpszProxy, "http", &pi->http, gc);
      parse_windows_proxy_setting_list (info->lpszProxy, "socks", &pi->socks, gc);
      break;
    default:
      if (err)
	*err = "PROXY: unknown proxy type";
      break;
    }

 done:
  gc_free (&gc_local);
  return pi;
}

#else

struct auto_proxy_info *
get_proxy_settings (char **err, struct gc_arena *gc)
{
#if 1
  if (err)
    *err = string_alloc ("PROXY: automatic detection not supported on this OS", gc);
  return NULL;
#else /* test --auto-proxy feature */
  struct auto_proxy_info *pi;
  ALLOC_OBJ_CLEAR_GC (pi, struct auto_proxy_info, gc);
  pi->http.server = "10.10.0.2";
  pi->http.port = 4000;
  return pi;
#endif
}

#endif

#endif /* GENERAL_PROXY_SUPPORT */
