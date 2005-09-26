/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2005 OpenVPN Solutions LLC <info@openvpn.net>
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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#ifdef ENABLE_HTTP_PROXY

#include "syshead.h"

#include "common.h"
#include "misc.h"
#include "win32.h"
#include "socket.h"
#include "fdmisc.h"
#include "proxy.h"
#include "ntlm.h"

#include "memdbg.h"

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
  static const char base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  uint8_t *buf;
  const uint8_t *src;
  uint8_t *dst;
  int bits, data, dst_len;

  /* make base64 string */
  dst_len = (src_len + 2) / 3 * 4;
  buf = gc_malloc (dst_len + 1, false, gc);
  bits = data = 0;
  src = str;
  dst = buf;
  while (dst_len--)
    {
      if (bits < 6)
	{
	  data = (data << 8) | *src;
	  bits += 8;
	  src++;
	}
      *dst++ = base64_table[0x3F & (data >> (bits - 6))];
      bits -= 6;
    }
  *dst = '\0';

  /* fix-up tail padding */
  switch (src_len % 3)
    {
    case 1:
      *--dst = '=';
    case 2:
      *--dst = '=';
    }
  return buf;
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

struct http_proxy_info *
new_http_proxy (const struct http_proxy_options *o,
		struct gc_arena *gc)
{
  struct http_proxy_info *p;
  ALLOC_OBJ_CLEAR_GC (p, struct http_proxy_info, gc);

  if (!o->server)
    msg (M_FATAL, "HTTP_PROXY: server not specified");

  ASSERT (legal_ipv4_port (o->port));

  p->options = *o;

  /* parse authentication method */
  p->auth_method = HTTP_AUTH_NONE;
  if (o->auth_method_string)
    {
      if (!strcmp (o->auth_method_string, "none"))
	p->auth_method = HTTP_AUTH_NONE;
      else if (!strcmp (o->auth_method_string, "basic"))
	p->auth_method = HTTP_AUTH_BASIC;
      else if (!strcmp (o->auth_method_string, "ntlm"))
	p->auth_method = HTTP_AUTH_NTLM;
      else
	msg (M_FATAL, "ERROR: unknown HTTP authentication method: '%s' -- only the 'none', 'basic', or 'ntlm' methods are currently supported",
	     o->auth_method_string);
    }

  /* only basic and NTLM authentication supported so far */
  if (p->auth_method == HTTP_AUTH_BASIC || p->auth_method == HTTP_AUTH_NTLM)
    {
      get_user_pass (&static_proxy_user_pass,
		     o->auth_file,
		     false,
		     "HTTP Proxy",
		     GET_USER_PASS_MANAGEMENT);
      p->up = static_proxy_user_pass;
    }

#if !NTLM
  if (p->auth_method == HTTP_AUTH_NTLM)
    msg (M_FATAL, "Sorry, this version of " PACKAGE_NAME " was built without NTLM Proxy support.");
#endif

  p->defined = true;
  return p;
}

void
establish_http_proxy_passthru (struct http_proxy_info *p,
			       socket_descriptor_t sd, /* already open to proxy */
			       const char *host,       /* openvpn server remote */
			       const int port,         /* openvpn server port */
			       struct buffer *lookahead,
			       volatile int *signal_received)
{
  struct gc_arena gc = gc_new ();
  char buf[256];
  char buf2[128];
  char get[80];
  int status;
  int nparms;

  /* format HTTP CONNECT message */
  openvpn_snprintf (buf, sizeof(buf), "CONNECT %s:%d HTTP/%s",
		    host,
		    port,
		    p->options.http_version);

  msg (D_PROXY, "Send to HTTP proxy: '%s'", buf);

  /* send HTTP CONNECT message to proxy */
  if (!send_line_crlf (sd, buf))
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
      openvpn_sleep (1);
      if (!send_line_crlf (sd, buf))
	goto error;
      break;

#if NTLM
    case HTTP_AUTH_NTLM:
      openvpn_snprintf (buf, sizeof(buf), "Proxy-Authorization: NTLM %s",
			ntlm_phase_1 (p, &gc));
      msg (D_PROXY, "Attempting NTLM Proxy-Authorization phase 1");
      dmsg (D_SHOW_KEYS, "Send to HTTP proxy: '%s'", buf);
      openvpn_sleep (1);
      if (!send_line_crlf (sd, buf))
	goto error;
      break;
#endif

    default:
      ASSERT (0);
    }

  /* send empty CR, LF */
  openvpn_sleep (1);
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

  /* check for a "407 Proxy Authentication Required" response */
  if (nparms >= 1 && status == 407)
    {
      msg (D_PROXY, "Proxy requires authentication");

      /* check for NTLM */
      if (p->auth_method == HTTP_AUTH_NTLM)
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
          while (recv_line (sd, NULL, 0, p->options.timeout, true, NULL, signal_received))
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

          /* send HOST etc, */
          openvpn_sleep (1);
          openvpn_snprintf (buf, sizeof(buf), "Host: %s", host);
          msg (D_PROXY, "Send to HTTP proxy: '%s'", buf);
          if (!send_line_crlf (sd, buf))
            goto error;

          openvpn_snprintf (buf, sizeof(buf), "Proxy-Authorization: NTLM %s",
			    ntlm_phase_3 (p, buf2, &gc));
          msg (D_PROXY, "Attempting NTLM Proxy-Authorization phase 3");
          msg (D_PROXY, "Send to HTTP proxy: '%s'", buf);
          openvpn_sleep (1);
          if (!send_line_crlf (sd, buf))
	    goto error;
          /* ok so far... */
          /* send empty CR, LF */
          openvpn_sleep (1);
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
#else
	  ASSERT (0); /* No NTLM support */
#endif
	}
      else goto error;
    }


  /* check return code, success = 200 */
  if (nparms < 1 || status != 200)
    {
      msg (D_LINK_ERRORS, "HTTP proxy returned bad status");
#if 0 
      /* DEBUGGING -- show a multi-line HTTP error response */
      while (true)
	{
	  if (!recv_line (sd, buf, sizeof (buf), p->options.timeout, true, NULL, signal_received))
	    goto error;
	  chomp (buf);
	  msg (D_PROXY, "HTTP proxy returned: '%s'", buf);
	}
#endif
      goto error;
    }

  /* receive line from proxy and discard */
  if (!recv_line (sd, NULL, 0, p->options.timeout, true, NULL, signal_received))
    goto error;

  /*
   * Toss out any extraneous chars, but don't throw away the
   * start of the OpenVPN data stream (put it in lookahead).
   */
  while (recv_line (sd, NULL, 0, 2, false, lookahead, signal_received))
    ;

#if 0
  if (lookahead && BLEN (lookahead))
    msg (M_INFO, "HTTP PROXY: lookahead: %s", format_hex (BPTR (lookahead), BLEN (lookahead), 0));
#endif

  gc_free (&gc);
  return;

 error:
  /* on error, should we exit or restart? */
  if (!*signal_received)
    *signal_received = (p->options.retry ? SIGUSR1 : SIGTERM); /* SOFT-SIGUSR1 -- HTTP proxy error */
  gc_free (&gc);
  return;
}

#else
static void dummy(void) {}
#endif /* ENABLE_HTTP_PROXY */
