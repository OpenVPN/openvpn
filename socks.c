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

/*
 * 2004-01-30: Added Socks5 proxy support, see RFC 1928
 *   (Christof Meerwald, http://cmeerw.org)
 *
 * 2010-10-10: Added Socks5 plain text authentication support (RFC 1929)
 *   (Pierre Bourdon <delroth@gmail.com>)
 */

#include "syshead.h"

#ifdef ENABLE_SOCKS

#include "common.h"
#include "misc.h"
#include "win32.h"
#include "socket.h"
#include "fdmisc.h"
#include "misc.h"
#include "proxy.h"

#include "memdbg.h"

#define UP_TYPE_SOCKS		"SOCKS Proxy"

void
socks_adjust_frame_parameters (struct frame *frame, int proto)
{
  if (proto == PROTO_UDPv4)
    frame_add_to_extra_link (frame, 10);
}

struct socks_proxy_info *
socks_proxy_new (const char *server,
		 int port,
		 const char *authfile,
		 bool retry,
		 struct auto_proxy_info *auto_proxy_info)
{
  struct socks_proxy_info *p;

  if (auto_proxy_info)
    {
      if (!server)
	{
	  if (!auto_proxy_info->socks.server)
	    return NULL;

	  server = auto_proxy_info->socks.server;
	  port = auto_proxy_info->socks.port;
	}
    }

  ALLOC_OBJ_CLEAR (p, struct socks_proxy_info);

  ASSERT (server);
  ASSERT (legal_ipv4_port (port));

  strncpynt (p->server, server, sizeof (p->server));
  p->port = port;

  if (authfile)
    strncpynt (p->authfile, authfile, sizeof (p->authfile));
  else
    p->authfile[0] = 0;

  p->retry = retry;
  p->defined = true;

  return p;
}

void
socks_proxy_close (struct socks_proxy_info *sp)
{
  free (sp);
}

static bool
socks_username_password_auth (struct socks_proxy_info *p,
                              socket_descriptor_t sd,
                              volatile int *signal_received)
{
  char to_send[516];
  char buf[2];
  int len = 0;
  const int timeout_sec = 5;
  struct user_pass creds;
  ssize_t size;

  creds.defined = 0;
  get_user_pass (&creds, p->authfile, UP_TYPE_SOCKS, GET_USER_PASS_MANAGEMENT);

  if( !creds.username || (strlen(creds.username) > 255)
      || !creds.password || (strlen(creds.password) > 255) ) {
          msg (M_NONFATAL,
               "SOCKS username and/or password exceeds 255 characters.  "
               "Authentication not possible.");
          return false;
  }
  openvpn_snprintf (to_send, sizeof (to_send), "\x01%c%s%c%s", (int) strlen(creds.username),
            creds.username, (int) strlen(creds.password), creds.password);
  size = send (sd, to_send, strlen(to_send), MSG_NOSIGNAL);

  if (size != strlen (to_send))
    {
      msg (D_LINK_ERRORS | M_ERRNO_SOCK, "socks_username_password_auth: TCP port write failed on send()");
      return false;
    }

  while (len < 2)
    {
      int status;
      ssize_t size;
      fd_set reads;
      struct timeval tv;
      char c;

      FD_ZERO (&reads);
      FD_SET (sd, &reads);
      tv.tv_sec = timeout_sec;
      tv.tv_usec = 0;

      status = select (sd + 1, &reads, NULL, NULL, &tv);

      get_signal (signal_received);
      if (*signal_received)
	return false;

      /* timeout? */
      if (status == 0)
	{
	  msg (D_LINK_ERRORS | M_ERRNO_SOCK, "socks_username_password_auth: TCP port read timeout expired");
	  return false;
	}

      /* error */
      if (status < 0)
	{
	  msg (D_LINK_ERRORS | M_ERRNO_SOCK, "socks_username_password_auth: TCP port read failed on select()");
	  return false;
	}

      /* read single char */
      size = recv(sd, &c, 1, MSG_NOSIGNAL);

      /* error? */
      if (size != 1)
	{
	  msg (D_LINK_ERRORS | M_ERRNO_SOCK, "socks_username_password_auth: TCP port read failed on recv()");
	  return false;
	}

      /* store char in buffer */
      buf[len++] = c;
    }

  /* VER = 5, SUCCESS = 0 --> auth success */
  if (buf[0] != 5 && buf[1] != 0)
  {
    msg (D_LINK_ERRORS, "socks_username_password_auth: server refused the authentication");
    return false;
  }

  return true;
}

static bool
socks_handshake (struct socks_proxy_info *p,
                 socket_descriptor_t sd,
                 volatile int *signal_received)
{
  char buf[2];
  int len = 0;
  const int timeout_sec = 5;

  /* VER = 5, NMETHODS = 2, METHODS = [0 (no auth), 2 (plain login)] */
  const ssize_t size = send (sd, "\x05\x02\x00\x02", 4, MSG_NOSIGNAL);
  if (size != 4)
    {
      msg (D_LINK_ERRORS | M_ERRNO_SOCK, "socks_handshake: TCP port write failed on send()");
      return false;
    }

  while (len < 2)
    {
      int status;
      ssize_t size;
      fd_set reads;
      struct timeval tv;
      char c;

      FD_ZERO (&reads);
      FD_SET (sd, &reads);
      tv.tv_sec = timeout_sec;
      tv.tv_usec = 0;

      status = select (sd + 1, &reads, NULL, NULL, &tv);

      get_signal (signal_received);
      if (*signal_received)
	return false;

      /* timeout? */
      if (status == 0)
	{
	  msg (D_LINK_ERRORS | M_ERRNO_SOCK, "socks_handshake: TCP port read timeout expired");
	  return false;
	}

      /* error */
      if (status < 0)
	{
	  msg (D_LINK_ERRORS | M_ERRNO_SOCK, "socks_handshake: TCP port read failed on select()");
	  return false;
	}

      /* read single char */
      size = recv(sd, &c, 1, MSG_NOSIGNAL);

      /* error? */
      if (size != 1)
	{
	  msg (D_LINK_ERRORS | M_ERRNO_SOCK, "socks_handshake: TCP port read failed on recv()");
	  return false;
	}

      /* store char in buffer */
      buf[len++] = c;
    }

  /* VER == 5 */
  if (buf[0] != '\x05')
    {
      msg (D_LINK_ERRORS, "socks_handshake: Socks proxy returned bad status");
      return false;
    }

  /* select the appropriate authentication method */
  switch (buf[1])
    {
    case 0: /* no authentication */
      break;

    case 2: /* login/password */
      if (!p->authfile[0])
      {
	msg(D_LINK_ERRORS, "socks_handshake: server asked for username/login auth but we were "
	                   "not provided any credentials");
	return false;
      }

      if (!socks_username_password_auth(p, sd, signal_received))
	return false;

      break;

    default: /* unknown auth method */
      msg(D_LINK_ERRORS, "socks_handshake: unknown SOCKS auth method");
      return false;
    }

  return true;
}

static bool
recv_socks_reply (socket_descriptor_t sd,
		  struct openvpn_sockaddr *addr,
		  volatile int *signal_received)
{
  char atyp = '\0';
  int alen = 0;
  int len = 0;
  char buf[22];
  const int timeout_sec = 5;

  if (addr != NULL)
    {
      addr->sa.sin_family = AF_INET;
      addr->sa.sin_addr.s_addr = htonl (INADDR_ANY);
      addr->sa.sin_port = htons (0);
    }

  while (len < 4 + alen + 2)
    {
      int status;
      ssize_t size;
      fd_set reads;
      struct timeval tv;
      char c;

      FD_ZERO (&reads);
      FD_SET (sd, &reads);
      tv.tv_sec = timeout_sec;
      tv.tv_usec = 0;

      status = select (sd + 1, &reads, NULL, NULL, &tv);

      get_signal (signal_received);
      if (*signal_received)
	return false;

      /* timeout? */
      if (status == 0)
	{
	  msg (D_LINK_ERRORS | M_ERRNO_SOCK, "recv_socks_reply: TCP port read timeout expired");
	  return false;
	}

      /* error */
      if (status < 0)
	{
	  msg (D_LINK_ERRORS | M_ERRNO_SOCK, "recv_socks_reply: TCP port read failed on select()");
	  return false;
	}

      /* read single char */
      size = recv(sd, &c, 1, MSG_NOSIGNAL);

      /* error? */
      if (size != 1)
	{
	  msg (D_LINK_ERRORS | M_ERRNO_SOCK, "recv_socks_reply: TCP port read failed on recv()");
	  return false;
	}

      if (len == 3)
	atyp = c;

      if (len == 4)
	{
	  switch (atyp)
	    {
	    case '\x01':	/* IP V4 */
	      alen = 4;
	      break;

	    case '\x03':	/* DOMAINNAME */
	      alen = (unsigned char) c;
	      break;

	    case '\x04':	/* IP V6 */
	      alen = 16;
	      break;

	    default:
	      msg (D_LINK_ERRORS, "recv_socks_reply: Socks proxy returned bad address type");
	      return false;
	    }
	}

      /* store char in buffer */
      if (len < (int)sizeof(buf))
	buf[len] = c;
      ++len;
    }

  /* VER == 5 && REP == 0 (succeeded) */
  if (buf[0] != '\x05' || buf[1] != '\x00')
    {
      msg (D_LINK_ERRORS, "recv_socks_reply: Socks proxy returned bad reply");
      return false;
    }

  /* ATYP == 1 (IP V4 address) */
  if (atyp == '\x01' && addr != NULL)
    {
      memcpy (&addr->sa.sin_addr, buf + 4, sizeof (addr->sa.sin_addr));
      memcpy (&addr->sa.sin_port, buf + 8, sizeof (addr->sa.sin_port));
    }


  return true;
}

void
establish_socks_proxy_passthru (struct socks_proxy_info *p,
			        socket_descriptor_t sd, /* already open to proxy */
			        const char *host,       /* openvpn server remote */
			        const int port,         /* openvpn server port */
			        volatile int *signal_received)
{
  char buf[128];
  size_t len;

  if (!socks_handshake (p, sd, signal_received))
    goto error;

  /* format Socks CONNECT message */
  buf[0] = '\x05';		/* VER = 5 */
  buf[1] = '\x01';		/* CMD = 1 (CONNECT) */
  buf[2] = '\x00';		/* RSV */
  buf[3] = '\x03';		/* ATYP = 3 (DOMAINNAME) */

  len = strlen(host);
  len = (5 + len + 2 > sizeof(buf)) ? (sizeof(buf) - 5 - 2) : len;

  buf[4] = (char) len;
  memcpy(buf + 5, host, len);

  buf[5 + len] = (char) (port >> 8);
  buf[5 + len + 1] = (char) (port & 0xff);

  {
    const ssize_t size = send (sd, buf, 5 + len + 2, MSG_NOSIGNAL);
    if ((int)size != 5 + (int)len + 2)
      {
	msg (D_LINK_ERRORS | M_ERRNO_SOCK, "establish_socks_proxy_passthru: TCP port write failed on send()");
	goto error;
      }
  }

  /* receive reply from Socks proxy and discard */
  if (!recv_socks_reply (sd, NULL, signal_received))
    goto error;

  return;

 error:
  /* on error, should we exit or restart? */
  if (!*signal_received)
    *signal_received = (p->retry ? SIGUSR1 : SIGTERM); /* SOFT-SIGUSR1 -- socks error */
  return;
}

void
establish_socks_proxy_udpassoc (struct socks_proxy_info *p,
			        socket_descriptor_t ctrl_sd, /* already open to proxy */
				socket_descriptor_t udp_sd,
				struct openvpn_sockaddr *relay_addr,
			        volatile int *signal_received)
{
  if (!socks_handshake (p, ctrl_sd, signal_received))
    goto error;

  {
    /* send Socks UDP ASSOCIATE message */
    /* VER = 5, CMD = 3 (UDP ASSOCIATE), RSV = 0, ATYP = 1 (IP V4),
       BND.ADDR = 0, BND.PORT = 0 */
    const ssize_t size = send (ctrl_sd,
			       "\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00",
			       10, MSG_NOSIGNAL);
    if (size != 10)
      {
	msg (D_LINK_ERRORS | M_ERRNO_SOCK, "establish_socks_proxy_passthru: TCP port write failed on send()");
	goto error;
      }
  }

  /* receive reply from Socks proxy */
  CLEAR (*relay_addr);
  if (!recv_socks_reply (ctrl_sd, relay_addr, signal_received))
    goto error;

  return;

 error:
  /* on error, should we exit or restart? */
  if (!*signal_received)
    *signal_received = (p->retry ? SIGUSR1 : SIGTERM); /* SOFT-SIGUSR1 -- socks error */
  return;
}

/*
 * Remove the 10 byte socks5 header from an incoming
 * UDP packet, setting *from to the source address.
 *
 * Run after UDP read.
 */
void
socks_process_incoming_udp (struct buffer *buf,
			    struct link_socket_actual *from)
{
  int atyp;

  if (BLEN (buf) < 10)
    goto error;

  buf_read_u16 (buf);
  if (buf_read_u8 (buf) != 0)
    goto error;

  atyp = buf_read_u8 (buf);
  if (atyp != 1)		/* ATYP == 1 (IP V4) */
    goto error;

  buf_read (buf, &from->dest.sa.sin_addr, sizeof (from->dest.sa.sin_addr));
  buf_read (buf, &from->dest.sa.sin_port, sizeof (from->dest.sa.sin_port));

  return;

 error:
  buf->len = 0;
}

/*
 * Add a 10 byte socks header prior to UDP write.
 * *to is the destination address.
 *
 * Run before UDP write.
 * Returns the size of the header.
 */
int
socks_process_outgoing_udp (struct buffer *buf,
			    const struct link_socket_actual *to)
{
  /* 
   * Get a 10 byte subset buffer prepended to buf --
   * we expect these bytes will be here because
   * we allocated frame space in socks_adjust_frame_parameters.
   */
  struct buffer head = buf_sub (buf, 10, true);

  /* crash if not enough headroom in buf */
  ASSERT (buf_defined (&head));

  buf_write_u16 (&head, 0);	/* RSV = 0 */
  buf_write_u8 (&head, 0);	/* FRAG = 0 */
  buf_write_u8 (&head, '\x01'); /* ATYP = 1 (IP V4) */
  buf_write (&head, &to->dest.sa.sin_addr, sizeof (to->dest.sa.sin_addr));
  buf_write (&head, &to->dest.sa.sin_port, sizeof (to->dest.sa.sin_port));

  return 10;
}

#else
static void dummy(void) {}
#endif /* ENABLE_SOCKS */
