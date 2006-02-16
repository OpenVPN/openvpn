/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

#include "syshead.h"

#if PORT_SHARE

#include "event.h"
#include "socket.h"
#include "fdmisc.h"
#include "ps.h"

#include "memdbg.h"

struct port_share *port_share = NULL; /* GLOBAL */

/* size of i/o buffers */
#define PROXY_CONNECTION_BUFFER_SIZE 1500

/* Command codes for foreground -> background communication */
#define COMMAND_REDIRECT 10
#define COMMAND_EXIT     11

/* Response codes for background -> foreground communication */
#define RESPONSE_INIT_SUCCEEDED   20
#define RESPONSE_INIT_FAILED      21

/* A foreign (non-OpenVPN) connection we are proxying,
   usually HTTPS */
struct proxy_connection {
  bool defined;
  struct proxy_connection *next;
  struct proxy_connection *counterpart;
  struct buffer buf;
  bool buffer_initial;
  int rwflags;
  int sd;
};

/* used for passing fds between processes */
union fdmsg {
  struct cmsghdr h;
  char buf[CMSG_SPACE(sizeof(socket_descriptor_t))];
};

#if 0
static const char *
headc (const struct buffer *buf)
{
  static char foo[16];
  strncpy (foo, BSTR(buf), 15);
  foo[15] = 0;
  return foo;
}
#endif

static void
close_socket_if_defined (const socket_descriptor_t sd)
{
  if (socket_defined (sd))
    openvpn_close_socket (sd);
}

/*
 * Close most of parent's fds.
 * Keep stdin/stdout/stderr, plus one
 * other fd which is presumed to be
 * our pipe back to parent.
 * Admittedly, a bit of a kludge,
 * but posix doesn't give us a kind
 * of FD_CLOEXEC which will stop
 * fds from crossing a fork().
 */
static void
close_fds_except (int keep)
{
  socket_descriptor_t i;
  closelog ();
  for (i = 3; i <= 100; ++i)
    {
      if (i != keep)
	openvpn_close_socket (i);
    }
}

/*
 * Usually we ignore signals, because our parent will
 * deal with them.
 */
static void
set_signals (void)
{
  signal (SIGTERM, SIG_DFL);

  signal (SIGINT, SIG_IGN);
  signal (SIGHUP, SIG_IGN);
  signal (SIGUSR1, SIG_IGN);
  signal (SIGUSR2, SIG_IGN);
  signal (SIGPIPE, SIG_IGN);
}

/*
 * Socket read/write functions.
 */

static int
recv_control (const socket_descriptor_t fd)
{
  unsigned char c;
  const ssize_t size = read (fd, &c, sizeof (c));
  if (size == sizeof (c))
    return c;
  else
    {
      return -1;
    }
}

static int
send_control (const socket_descriptor_t fd, int code)
{
  unsigned char c = (unsigned char) code;
  const ssize_t size = write (fd, &c, sizeof (c));
  if (size == sizeof (c))
    return (int) size;
  else
    return -1;
}

static void
port_share_sendmsg (const socket_descriptor_t sd,
		    const char command,
		    const struct buffer *head,
		    const socket_descriptor_t sd_send)
{
  if (socket_defined (sd))
    {
      struct msghdr mesg;
      union fdmsg cmsg;
      struct cmsghdr* h;
      struct iovec iov[2];
      socket_descriptor_t sd_null[2] = { SOCKET_UNDEFINED, SOCKET_UNDEFINED };
      char cmd;
      ssize_t status;

      dmsg (D_PS_PROXY_DEBUG, "PORT SHARE: sendmsg sd=%d len=%d",
	    sd_send,
	    head ? BLEN(head) : -1);

      CLEAR (mesg);

      cmd = command;

      iov[0].iov_base = &cmd;
      iov[0].iov_len = sizeof (cmd);
      mesg.msg_iovlen = 1;

      if (head)
	{
	  iov[1].iov_base = BPTR (head);
	  iov[1].iov_len = BLEN (head);
	  mesg.msg_iovlen = 2;
	}

      mesg.msg_iov = iov;

      mesg.msg_control = cmsg.buf;
      mesg.msg_controllen = sizeof (union fdmsg);
      mesg.msg_flags = 0;

      h = CMSG_FIRSTHDR(&mesg);
      h->cmsg_level = SOL_SOCKET;
      h->cmsg_type = SCM_RIGHTS;
      h->cmsg_len = CMSG_LEN(sizeof(socket_descriptor_t));

      if (socket_defined (sd_send))
	{
	  *((socket_descriptor_t*)CMSG_DATA(h)) = sd_send;
	}
      else
	{
	  socketpair (PF_UNIX, SOCK_DGRAM, 0, sd_null);
	  *((socket_descriptor_t*)CMSG_DATA(h)) = sd_null[0];
	}

      status = sendmsg (sd, &mesg, MSG_NOSIGNAL);
      if (status == -1)
	msg (M_WARN, "PORT SHARE: sendmsg failed (unable to communicate with background process)");

      close_socket_if_defined (sd_null[0]);
      close_socket_if_defined (sd_null[1]);
    }
}

static int
pc_list_len (struct proxy_connection *pc)
{
  int count = 0;
  while (pc)
    {
      ++count;
      pc = pc->next;
    }
  return count;
}

/* mark a proxy entry and its counterpart for close */
static void
proxy_entry_mark_for_close (struct proxy_connection *pc, struct event_set *es)
{
  if (pc->defined)
    {
      struct proxy_connection *cp = pc->counterpart;
      dmsg (D_PS_PROXY_DEBUG, "PORT SHARE PROXY: delete sd=%d", pc->sd);
      if (socket_defined (pc->sd))
	{
	  if (es)
	    event_del (es, pc->sd);
	  openvpn_close_socket (pc->sd);
	  pc->sd = SOCKET_UNDEFINED;
	}
      free_buf (&pc->buf);
      pc->buffer_initial = false;
      pc->rwflags = 0;
      pc->counterpart = NULL;
      pc->defined = false;
      if (cp && cp->defined && cp->counterpart == pc)
	proxy_entry_mark_for_close (cp, es);
    }
}

static void
proxy_list_housekeeping (struct proxy_connection **list)
{
  if (list)
    {
      struct proxy_connection *prev = NULL;
      struct proxy_connection *pc = *list;

      while (pc)
	{
	  struct proxy_connection *next = pc->next;
	  if (!pc->defined)
	    {
	      free (pc);
	      if (prev)
		prev->next = next;
	      else
		*list = next;
	    }
	  else
	    prev = pc;
	  pc = next;
	}
    }
}

static void
proxy_list_close (struct proxy_connection **list)
{
  if (list)
    {
      struct proxy_connection *pc = *list;
      while (pc)
	{
	  proxy_entry_mark_for_close (pc, NULL);
	  pc = pc->next;
	}
      proxy_list_housekeeping (list);
    }
}

static void
sock_addr_set (struct openvpn_sockaddr *osaddr,
	       const in_addr_t addr,
	       const int port)
{
  CLEAR (*osaddr);
  osaddr->sa.sin_family = AF_INET;
  osaddr->sa.sin_addr.s_addr = htonl (addr);
  osaddr->sa.sin_port = htons (port);
}

static inline void
proxy_connection_io_requeue (struct proxy_connection *pc, const int rwflags_new, struct event_set *es)
{
  if (pc->rwflags != rwflags_new)
    {
      event_ctl (es, pc->sd, rwflags_new, (void*)pc);
      pc->rwflags = rwflags_new;
    }
}

static bool
proxy_entry_new (struct proxy_connection **list,
		 struct event_set *es,
		 const in_addr_t server_addr,
		 const int server_port,
		 const socket_descriptor_t sd_client,
		 struct buffer *initial_data)
{
  struct openvpn_sockaddr osaddr;
  socket_descriptor_t sd_server;
  int status;
  struct proxy_connection *pc;
  struct proxy_connection *cp;

  /* connect to port share server */
  sock_addr_set (&osaddr, server_addr, server_port);
  sd_server = create_socket_tcp ();
  status = openvpn_connect (sd_server, &osaddr, 5, NULL);
  if (status)
    {
      msg (M_WARN, "PORT SHARE PROXY: connect to port-share server failed");
      openvpn_close_socket (sd_server);
      return false;
    }
  dmsg (D_PS_PROXY_DEBUG, "PORT SHARE PROXY: connect to port-share server succeeded");

  set_nonblock (sd_client);
  set_nonblock (sd_server);

  /* allocate 2 new proxy_connection objects */
  ALLOC_OBJ_CLEAR (pc, struct proxy_connection);
  ALLOC_OBJ_CLEAR (cp, struct proxy_connection);

  /* client object */
  pc->defined = true;
  pc->next = cp;
  pc->counterpart = cp;
  pc->buf = *initial_data;
  pc->buffer_initial = true;
  pc->rwflags = EVENT_UNDEF;
  pc->sd = sd_client;

  /* server object */
  cp->defined = true;
  cp->next = *list;
  cp->counterpart = pc;
  cp->buf = alloc_buf (PROXY_CONNECTION_BUFFER_SIZE);
  cp->buffer_initial = false;
  cp->rwflags = EVENT_UNDEF;
  cp->sd = sd_server;

  /* add to list */
  *list = pc;
  
  dmsg (D_PS_PROXY_DEBUG, "PORT SHARE PROXY: NEW CONNECTION [c=%d s=%d]", sd_client, sd_server);

  /* set initial i/o states */
  proxy_connection_io_requeue (pc, EVENT_READ, es);
  proxy_connection_io_requeue (cp, EVENT_READ|EVENT_WRITE, es);
  
  return true;
}

static bool
control_message_from_parent (const socket_descriptor_t sd_control,
			     struct proxy_connection **list,
			     struct event_set *es,
			     const in_addr_t server_addr,
			     const int server_port)
{
  struct buffer buf = alloc_buf (PROXY_CONNECTION_BUFFER_SIZE);
  struct msghdr mesg;
  union fdmsg cmsg;
  struct cmsghdr* h;
  struct iovec iov[2];
  char command = 0;
  ssize_t status;
  int ret = true;

  CLEAR (mesg);

  iov[0].iov_base = &command;
  iov[0].iov_len = sizeof (command);
  iov[1].iov_base = BPTR (&buf);
  iov[1].iov_len = BCAP (&buf);
  mesg.msg_iov = iov;
  mesg.msg_iovlen = 2;

  mesg.msg_control = cmsg.buf;
  mesg.msg_controllen = sizeof (union fdmsg);
  mesg.msg_flags = 0;

  h = CMSG_FIRSTHDR(&mesg);
  h->cmsg_len = CMSG_LEN(sizeof(socket_descriptor_t));
  h->cmsg_level = SOL_SOCKET;
  h->cmsg_type = SCM_RIGHTS;
  *((socket_descriptor_t*)CMSG_DATA(h)) = SOCKET_UNDEFINED;

  status = recvmsg (sd_control, &mesg, MSG_NOSIGNAL);
  if (status != -1)
    {
      if (   h == NULL
	  || h->cmsg_len    != CMSG_LEN(sizeof(socket_descriptor_t))
	  || h->cmsg_level  != SOL_SOCKET
	  || h->cmsg_type   != SCM_RIGHTS )
	{
	  ret = false;
	}
      else
	{
	  const socket_descriptor_t received_fd = *((socket_descriptor_t*)CMSG_DATA(h));
	  dmsg (D_PS_PROXY_DEBUG, "PORT SHARE PROXY: RECEIVED sd=%d", received_fd);

	  if (status >= 2 && command == COMMAND_REDIRECT)
	    {
	      buf.len = status - 1;
	      if (proxy_entry_new (list,
				   es,
				   server_addr,
				   server_port,
				   received_fd,
				   &buf))
		{
		  CLEAR (buf); /* we gave the buffer to proxy_entry_new */
		}
	      else
		{
		  openvpn_close_socket (received_fd);
		}
	    }
	  else if (status >= 1 && command == COMMAND_EXIT)
	    {
	      dmsg (D_PS_PROXY_DEBUG, "PORT SHARE PROXY: RECEIVED COMMAND_EXIT");
	      openvpn_close_socket (received_fd); /* null socket */
	      ret = false;
	    }
	}
    }
  free_buf (&buf);
  return ret;
}

/* proxy_connection_io_xfer return values */

#define IOSTAT_EAGAIN_ON_READ   0
#define IOSTAT_EAGAIN_ON_WRITE  1
#define IOSTAT_ERROR            2

/* forward data from pc to pc->counterpart */
static int
proxy_connection_io_xfer (struct proxy_connection *pc)
{
  while (true)
    {
      if (!BLEN (&pc->buf))
	{
	  /* recv data from socket */
	  ssize_t status = recv (pc->sd, BPTR(&pc->buf), BCAP(&pc->buf), MSG_NOSIGNAL);
	  if (status == -1)
	    {
	      return (errno == EAGAIN) ? IOSTAT_EAGAIN_ON_READ : IOSTAT_ERROR;
	    }
	  else
	    {
	      if (!status)
		return IOSTAT_ERROR;
	      pc->buf.len = status;
	    }
	}

      if (BLEN (&pc->buf))
	{
	  /* send data to counterpart socket */
	  ssize_t status = send (pc->counterpart->sd, BPTR(&pc->buf), BLEN(&pc->buf), MSG_NOSIGNAL);
	  if (status == -1)
	    {
	      const int e = errno;
	      return (e == EAGAIN) ? IOSTAT_EAGAIN_ON_WRITE : IOSTAT_ERROR;
	    }
	  else
	    {
	      if (status != pc->buf.len)
		return IOSTAT_ERROR;
	      pc->buf.len = 0;
	    }

	  /* successful send */
	  if (pc->buffer_initial)
	    {
	      free_buf (&pc->buf);
	      pc->buf = alloc_buf (PROXY_CONNECTION_BUFFER_SIZE);
	      pc->buffer_initial = false;
	    }
	}
    }
  return IOSTAT_ERROR;
}

static inline bool
proxy_connection_io_status (const int status, int *rwflags_pc, int *rwflags_cp)
{
  switch (status)
    {
	case IOSTAT_EAGAIN_ON_READ:
	  *rwflags_pc |= EVENT_READ;
	  *rwflags_cp &= ~EVENT_WRITE;
	  return true;
	case IOSTAT_EAGAIN_ON_WRITE:
	  *rwflags_pc &= ~EVENT_READ;
	  *rwflags_cp |= EVENT_WRITE;
	  return true;
	default:
	  return false;
    }
}

static bool
proxy_connection_io_dispatch (struct proxy_connection *pc,
			      const int rwflags,
			      struct event_set *es)
{
  struct proxy_connection *cp = pc->counterpart;
  int status;
  int rwflags_pc = pc->rwflags;
  int rwflags_cp = cp->rwflags;

  if (rwflags & EVENT_READ)
    {
      status = proxy_connection_io_xfer (pc);
      if (!proxy_connection_io_status (status, &rwflags_pc, &rwflags_cp))
	goto bad;
    }
  if (rwflags & EVENT_WRITE)
    {
      status = proxy_connection_io_xfer (cp);
      if (!proxy_connection_io_status (status, &rwflags_cp, &rwflags_pc))
	goto bad;
    }
  proxy_connection_io_requeue (pc, rwflags_pc, es);
  proxy_connection_io_requeue (cp, rwflags_cp, es);

  return true;

 bad:
  proxy_entry_mark_for_close (pc, es);
  return false;
}

static void
port_share_proxy (const in_addr_t hostaddr, const int port, const socket_descriptor_t sd_control)
{
  if (send_control (sd_control, RESPONSE_INIT_SUCCEEDED) >= 0)
    {
      void *sd_control_marker = (void *)1;
      int maxevents = 256;
      struct event_set *es;
      struct event_set_return esr[64];
      struct proxy_connection *list = NULL;
      time_t last_housekeeping = 0;

      msg (D_PS_PROXY, "PORT SHARE PROXY: proxy starting");

      es = event_set_init (&maxevents, 0);
      event_ctl (es, sd_control, EVENT_READ, sd_control_marker);
      while (true)
	{
	  int n_events;
	  struct timeval tv;
	  time_t current;

	  tv.tv_sec = 10;
	  tv.tv_usec = 0;
	  n_events = event_wait (es, &tv, esr, SIZE(esr));
	  current = time(NULL);
	  if (n_events > 0)
	    {
	      int i;
	      for (i = 0; i < n_events; ++i)
		{
		  const struct event_set_return *e = &esr[i];
		  if (e->arg == sd_control_marker)
		    {
		      if (!control_message_from_parent (sd_control, &list, es, hostaddr, port))
			goto done;
		    }
		  else
		    {
		      struct proxy_connection *pc = (struct proxy_connection *)e->arg;
		      if (pc->defined)
			proxy_connection_io_dispatch (pc, e->rwflags, es);
		    }
		}
	    }
	  else if (n_events < 0)
	    {
	      dmsg (D_PS_PROXY_DEBUG, "PORT SHARE PROXY: event_wait failed");
	    }
	  if (current > last_housekeeping)
	    {
	      proxy_list_housekeeping (&list);
	      last_housekeeping = current;
	    }
	}

    done:
      proxy_list_close (&list);
      event_free (es);
    }
  msg (D_PS_PROXY, "PORT SHARE PROXY: proxy exiting");
}

struct port_share *
port_share_open (const char *host, const int port)
{
  pid_t pid;
  socket_descriptor_t fd[2];
  in_addr_t hostaddr;
  struct port_share *ps;

  ALLOC_OBJ_CLEAR (ps, struct port_share);

  /*
   * Get host's IP address
   */
  hostaddr = getaddr (GETADDR_RESOLVE|GETADDR_HOST_ORDER|GETADDR_FATAL, host, 0, NULL, NULL);

  /*
   * Make a socket for foreground and background processes
   * to communicate.
   */
  if (socketpair (PF_UNIX, SOCK_DGRAM, 0, fd) == -1)
    {
      msg (M_WARN, "PORT SHARE: socketpair call failed");
      goto error;
    }

  /*
   * Fork off background proxy process.
   */
  pid = fork ();

  if (pid)
    {
      int status;

      /*
       * Foreground Process
       */

      ps->background_pid = pid;

      /* close our copy of child's socket */
      openvpn_close_socket (fd[1]);

      /* don't let future subprocesses inherit child socket */
      set_cloexec (fd[0]);

      /* wait for background child process to initialize */
      status = recv_control (fd[0]);
      if (status == RESPONSE_INIT_SUCCEEDED)
	{
	  ps->foreground_fd = fd[0];
	  return ps;
	}
    }
  else
    {
      /*
       * Background Process
       */

      /* Ignore most signals (the parent will receive them) */
      set_signals ();

      /* Let msg know that we forked */
      msg_forked ();

      /* close all parent fds except our socket back to parent */
      close_fds_except (fd[1]);

      /* no blocking on control channel back to parent */
      set_nonblock (fd[1]);

      /* execute the event loop */
      port_share_proxy (hostaddr, port, fd[1]);

      openvpn_close_socket (fd[1]);

      exit (0);
      return 0; /* NOTREACHED */
    }

 error:
  port_share_close (ps);
  return NULL;
}

void
port_share_close (struct port_share *ps)
{
  if (ps)
    {
      if (ps->foreground_fd >= 0)
	{
	  /* tell background process to exit */
	  port_share_sendmsg (ps->foreground_fd, COMMAND_EXIT, NULL, SOCKET_UNDEFINED);

	  /* wait for background process to exit */
	  dmsg (D_PS_PROXY_DEBUG, "PORT SHARE: waiting for background process to exit");
	  if (ps->background_pid > 0)
	    waitpid (ps->background_pid, NULL, 0);
	  dmsg (D_PS_PROXY_DEBUG, "PORT SHARE: background process exited");

	  openvpn_close_socket (ps->foreground_fd);
	  ps->foreground_fd = -1;
	}

      free (ps);
    }
}

void
port_share_abort (struct port_share *ps)
{
  if (ps)
    {
      /* tell background process to exit */
      if (ps->foreground_fd >= 0)
	{
	  send_control (ps->foreground_fd, COMMAND_EXIT);
	  openvpn_close_socket (ps->foreground_fd);
	  ps->foreground_fd = -1;
	}
    }
}

bool
is_openvpn_protocol (const struct buffer *buf)
{
  const unsigned char *p = BSTR (buf);
  const int len = BLEN (buf);
  if (len >= 3)
    {
      return p[0] == 0
	&& p[1] >= 14
	&& p[2] == (P_CONTROL_HARD_RESET_CLIENT_V2<<P_OPCODE_SHIFT);
    }
  else if (len >= 2)
    {
      return p[0] == 0 && p[1] >= 14;
    }
  else
    return true;
}

void
port_share_redirect (struct port_share *ps, const struct buffer *head, socket_descriptor_t sd)
{
  if (ps)
    port_share_sendmsg (ps->foreground_fd, COMMAND_REDIRECT, head, sd);
}

#endif
