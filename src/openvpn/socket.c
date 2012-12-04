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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "socket.h"
#include "fdmisc.h"
#include "misc.h"
#include "gremlin.h"
#include "plugin.h"
#include "ps.h"
#include "manage.h"
#include "misc.h"

#include "memdbg.h"

const int proto_overhead[] = { /* indexed by PROTO_x */
  0,
  IPv4_UDP_HEADER_SIZE, /* IPv4 */
  IPv4_TCP_HEADER_SIZE,
  IPv4_TCP_HEADER_SIZE,
  IPv6_UDP_HEADER_SIZE, /* IPv6 */
  IPv6_TCP_HEADER_SIZE,
  IPv6_TCP_HEADER_SIZE,
  IPv6_TCP_HEADER_SIZE,
};

/*
 * Convert sockflags/getaddr_flags into getaddr_flags
 */
static unsigned int
sf2gaf(const unsigned int getaddr_flags,
       const unsigned int sockflags)
{
  if (sockflags & SF_HOST_RANDOMIZE)
    return getaddr_flags | GETADDR_RANDOMIZE;
  else
    return getaddr_flags;
}

/*
 * Functions related to the translation of DNS names to IP addresses.
 */

static const char*
h_errno_msg(int h_errno_err)
{
  switch (h_errno_err)
    {
    case HOST_NOT_FOUND:
      return "[HOST_NOT_FOUND] The specified host is unknown.";
    case NO_DATA:
      return "[NO_DATA] The requested name is valid but does not have an IP address.";
    case NO_RECOVERY:
      return "[NO_RECOVERY] A non-recoverable name server error occurred.";
    case TRY_AGAIN:
      return "[TRY_AGAIN] A temporary error occurred on an authoritative name server.";
    }
  return "[unknown h_errno value]";
}

/*
 * Translate IP addr or hostname to in_addr_t.
 * If resolve error, try again for
 * resolve_retry_seconds seconds.
 */
in_addr_t
getaddr (unsigned int flags,
         const char *hostname,
         int resolve_retry_seconds,
         bool *succeeded,
         volatile int *signal_received)
{
  struct addrinfo *ai;
  int status;
  status = openvpn_getaddrinfo(flags, hostname, resolve_retry_seconds,
							   signal_received, AF_INET, &ai);
  if(status==0) {
    struct in_addr ia;
    if(succeeded)
      *succeeded=true;
    ia = ((struct sockaddr_in*)ai->ai_addr)->sin_addr;
    freeaddrinfo(ai);
    return (flags & GETADDR_HOST_ORDER) ? ntohl (ia.s_addr) : ia.s_addr;
  } else {
    if(succeeded)
      *succeeded =false;
    return 0;
  }
}


/*
 * Translate IPv4/IPv6 addr or hostname into struct addrinfo
 * If resolve error, try again for resolve_retry_seconds seconds.
 */
int
openvpn_getaddrinfo (unsigned int flags,
                     const char *hostname,
                     int resolve_retry_seconds,
                     volatile int *signal_received,
                     int ai_family,
                     struct addrinfo **res)
{
  struct addrinfo hints;
  int status;
  int sigrec = 0;
  int msglevel = (flags & GETADDR_FATAL) ? M_FATAL : D_RESOLVE_ERRORS;
  struct gc_arena gc = gc_new ();

  ASSERT(res);

#if defined(HAVE_RES_INIT)
  res_init ();
#endif

  if (!hostname)
    hostname = "::";

  if (flags & GETADDR_RANDOMIZE)
    hostname = hostname_randomize(hostname, &gc);

  if (flags & GETADDR_MSG_VIRT_OUT)
    msglevel |= M_MSG_VIRT_OUT;

  if ((flags & (GETADDR_FATAL_ON_SIGNAL|GETADDR_WARN_ON_SIGNAL))
      && !signal_received)
    signal_received = &sigrec;

  /* try numeric ipv6 addr first */
  CLEAR(hints);
  hints.ai_family = ai_family;
  hints.ai_flags = AI_NUMERICHOST;
  hints.ai_socktype = SOCK_STREAM;

  status = getaddrinfo(hostname, NULL, &hints, res);

  if (status != 0) /* parse as numeric address failed? */
    {
      const int fail_wait_interval = 5; /* seconds */
      int resolve_retries = (flags & GETADDR_TRY_ONCE) ? 1 : (resolve_retry_seconds / fail_wait_interval);
      const char *fmt;
      int level = 0;

      fmt = "RESOLVE: Cannot resolve host address: %s: %s";
      if ((flags & GETADDR_MENTION_RESOLVE_RETRY)
          && !resolve_retry_seconds)
        fmt = "RESOLVE: Cannot resolve host address: %s: %s (I would have retried this name query if you had specified the --resolv-retry option.)";

      if (!(flags & GETADDR_RESOLVE) || status == EAI_FAIL)
        {
          msg (msglevel, "RESOLVE: Cannot parse IP address: %s", hostname);
          goto done;
        }

#ifdef ENABLE_MANAGEMENT
      if (flags & GETADDR_UPDATE_MANAGEMENT_STATE)
        {
          if (management)
            management_set_state (management,
                                  OPENVPN_STATE_RESOLVE,
                                  NULL,
                                  (in_addr_t)0,
                                  (in_addr_t)0);
        }
#endif

      /*
       * Resolve hostname
       */
      while (true)
        {
          /* try hostname lookup */
          hints.ai_flags = 0;
          dmsg (D_SOCKET_DEBUG, "GETADDRINFO flags=0x%04x ai_family=%d ai_socktype=%d",
                flags, hints.ai_family, hints.ai_socktype);
          status = getaddrinfo(hostname, NULL, &hints, res);

          if (signal_received)
            {
              get_signal (signal_received);
              if (*signal_received) /* were we interrupted by a signal? */
                {
                  if (0 == status) {
                    ASSERT(res);
                    freeaddrinfo(*res);
                    res = NULL;
                  }
                  if (*signal_received == SIGUSR1) /* ignore SIGUSR1 */
                    {
                      msg (level, "RESOLVE: Ignored SIGUSR1 signal received during DNS resolution attempt");
                      *signal_received = 0;
                    }
                  else
                    goto done;
                }
            }

          /* success? */
          if (0 == status)
            break;

          /* resolve lookup failed, should we
             continue or fail? */
          level = msglevel;
          if (resolve_retries > 0)
            level = D_RESOLVE_ERRORS;

          msg (level,
               fmt,
               hostname,
               gai_strerror(status));

          if (--resolve_retries <= 0)
            goto done;

          openvpn_sleep (fail_wait_interval);
        }

      ASSERT(res);

      /* hostname resolve succeeded */

      /* Do not chose an IP Addresse by random or change the order *
       * of IP addresses, doing so will break RFC 3484 address selection *
       */
    }
  else
    {
      /* IP address parse succeeded */
    }

 done:
  if (signal_received && *signal_received)
    {
      int level = 0;
      if (flags & GETADDR_FATAL_ON_SIGNAL)
        level = M_FATAL;
      else if (flags & GETADDR_WARN_ON_SIGNAL)
        level = M_WARN;
      msg (level, "RESOLVE: signal received during DNS resolution attempt");
    }

  gc_free (&gc);
  return status;
}

/*
 * We do our own inet_aton because the glibc function
 * isn't very good about error checking.
 */
int
openvpn_inet_aton (const char *dotted_quad, struct in_addr *addr)
{
  unsigned int a, b, c, d;

  CLEAR (*addr);
  if (sscanf (dotted_quad, "%u.%u.%u.%u", &a, &b, &c, &d) == 4)
    {
      if (a < 256 && b < 256 && c < 256 && d < 256)
	{
	  addr->s_addr = htonl (a<<24 | b<<16 | c<<8 | d);
	  return OIA_IP; /* good dotted quad */
	}
    }
  if (string_class (dotted_quad, CC_DIGIT|CC_DOT, 0))
    return OIA_ERROR;    /* probably a badly formatted dotted quad */
  else
    return OIA_HOSTNAME; /* probably a hostname */
}

bool
ip_addr_dotted_quad_safe (const char *dotted_quad)
{
  /* verify non-NULL */
  if (!dotted_quad)
    return false;

  /* verify length is within limits */
  if (strlen (dotted_quad) > 15)
    return false;

  /* verify that all chars are either numeric or '.' and that no numeric
     substring is greater than 3 chars */
  {
    int nnum = 0;
    const char *p = dotted_quad;
    int c;

    while ((c = *p++))
      {
	if (c >= '0' && c <= '9')
	  {
	    ++nnum;
	    if (nnum > 3)
	      return false;
	  }
	else if (c == '.')
	  {
	    nnum = 0;
	  }
	else
	  return false;
      }
  }

  /* verify that string will convert to IP address */
  {
    struct in_addr a;
    return openvpn_inet_aton (dotted_quad, &a) == OIA_IP;
  }
}

bool
ipv6_addr_safe (const char *ipv6_text_addr)
{
  /* verify non-NULL */
  if (!ipv6_text_addr)
    return false;

  /* verify length is within limits */
  if (strlen (ipv6_text_addr) > INET6_ADDRSTRLEN )
    return false;

  /* verify that string will convert to IPv6 address */
  {
    struct in6_addr a6;
    return inet_pton( AF_INET6, ipv6_text_addr, &a6 ) == 1;
  }
}

static bool
dns_addr_safe (const char *addr)
{
  if (addr)
    {
      const size_t len = strlen (addr);
      return len > 0 && len <= 255 && string_class (addr, CC_ALNUM|CC_DASH|CC_DOT, 0);
    }
  else
    return false;
}

bool
ip_or_dns_addr_safe (const char *addr, const bool allow_fqdn)
{
  if (ip_addr_dotted_quad_safe (addr))
    return true;
  else if (allow_fqdn)
    return dns_addr_safe (addr);
  else
    return false;
}

bool
mac_addr_safe (const char *mac_addr)
{
  /* verify non-NULL */
  if (!mac_addr)
    return false;

  /* verify length is within limits */
  if (strlen (mac_addr) > 17)
    return false;

  /* verify that all chars are either alphanumeric or ':' and that no
     alphanumeric substring is greater than 2 chars */
  {
    int nnum = 0;
    const char *p = mac_addr;
    int c;

    while ((c = *p++))
      {
	if ( (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') )
	  {
	    ++nnum;
	    if (nnum > 2)
	      return false;
	  }
	else if (c == ':')
	  {
	    nnum = 0;
	  }
	else
	  return false;
      }
  }

  /* error-checking is left to script invoked in lladdr.c */
  return true;
}

static void
update_remote (const char* host,
	       struct openvpn_sockaddr *addr,
	       bool *changed,
	       const unsigned int sockflags)
{
  switch(addr->addr.sa.sa_family)
    {
    case AF_INET:
      if (host && addr)
	{
	  const in_addr_t new_addr = getaddr (
					      sf2gaf(GETADDR_RESOLVE|GETADDR_UPDATE_MANAGEMENT_STATE, sockflags),
					      host,
					      1,
					      NULL,
					      NULL);
	  if (new_addr && addr->addr.in4.sin_addr.s_addr != new_addr)
	    {
	      addr->addr.in4.sin_addr.s_addr = new_addr;
	      *changed = true;
	    }
	}
      break;
    case AF_INET6:
      if (host && addr)
        {
          int status;
          struct addrinfo* ai;

		  status = openvpn_getaddrinfo(sf2gaf(GETADDR_RESOLVE|GETADDR_UPDATE_MANAGEMENT_STATE, sockflags), host, 1, NULL, AF_INET6, &ai);

          if ( status ==0 )
            {
			  struct sockaddr_in6 sin6;
			  CLEAR(sin6);
			  sin6 = *((struct sockaddr_in6*)ai->ai_addr);
              if (!IN6_ARE_ADDR_EQUAL(&sin6.sin6_addr, &addr->addr.in6.sin6_addr))
              {
                int port = addr->addr.in6.sin6_port;
                /* ipv6 requires also eg. sin6_scope_id => easier to fully copy and override port */
                addr->addr.in6 = sin6; 
                addr->addr.in6.sin6_port = port;
              }
			  freeaddrinfo(ai);
            }
        }
      break;
    default:
        ASSERT(0);
  }
}

static int
socket_get_sndbuf (int sd)
{
#if defined(HAVE_GETSOCKOPT) && defined(SOL_SOCKET) && defined(SO_SNDBUF)
  int val;
  socklen_t len;

  len = sizeof (val);
  if (getsockopt (sd, SOL_SOCKET, SO_SNDBUF, (void *) &val, &len) == 0
      && len == sizeof (val))
    return val;
#endif
  return 0;
}

static void
socket_set_sndbuf (int sd, int size)
{
#if defined(HAVE_SETSOCKOPT) && defined(SOL_SOCKET) && defined(SO_SNDBUF)
  if (size > 0 && size < SOCKET_SND_RCV_BUF_MAX)
    {
      if (setsockopt (sd, SOL_SOCKET, SO_SNDBUF, (void *) &size, sizeof (size)) != 0)
	{
	  msg (M_WARN, "NOTE: setsockopt SO_SNDBUF=%d failed", size);
	}
    }
#endif
}

static int
socket_get_rcvbuf (int sd)
{
#if defined(HAVE_GETSOCKOPT) && defined(SOL_SOCKET) && defined(SO_RCVBUF)
  int val;
  socklen_t len;

  len = sizeof (val);
  if (getsockopt (sd, SOL_SOCKET, SO_RCVBUF, (void *) &val, &len) == 0
      && len == sizeof (val))
    return val;
#endif
  return 0;
}

static bool
socket_set_rcvbuf (int sd, int size)
{
#if defined(HAVE_SETSOCKOPT) && defined(SOL_SOCKET) && defined(SO_RCVBUF)
  if (size > 0 && size < SOCKET_SND_RCV_BUF_MAX)
    {
      if (setsockopt (sd, SOL_SOCKET, SO_RCVBUF, (void *) &size, sizeof (size)) != 0)
	{
	  msg (M_WARN, "NOTE: setsockopt SO_RCVBUF=%d failed", size);
	  return false;
	}
    }
  return true;
#endif
}

static void
socket_set_buffers (int fd, const struct socket_buffer_size *sbs)
{
  if (sbs)
    {
      const int sndbuf_old = socket_get_sndbuf (fd);
      const int rcvbuf_old = socket_get_rcvbuf (fd);

      if (sbs->sndbuf)
	socket_set_sndbuf (fd, sbs->sndbuf);

      if (sbs->rcvbuf)
	socket_set_rcvbuf (fd, sbs->rcvbuf);
       
      msg (D_OSBUF, "Socket Buffers: R=[%d->%d] S=[%d->%d]",
	   rcvbuf_old,
	   socket_get_rcvbuf (fd),
	   sndbuf_old,
	   socket_get_sndbuf (fd));
    }
}

/*
 * Set other socket options
 */

static bool
socket_set_tcp_nodelay (int sd, int state)
{
#if defined(WIN32) || (defined(HAVE_SETSOCKOPT) && defined(IPPROTO_TCP) && defined(TCP_NODELAY))
  if (setsockopt (sd, IPPROTO_TCP, TCP_NODELAY, (void *) &state, sizeof (state)) != 0)
    {
      msg (M_WARN, "NOTE: setsockopt TCP_NODELAY=%d failed", state);
      return false;
    }
  else
    {
      dmsg (D_OSBUF, "Socket flags: TCP_NODELAY=%d succeeded", state);
      return true;
    }
#else
  msg (M_WARN, "NOTE: setsockopt TCP_NODELAY=%d failed (No kernel support)", state);
  return false;
#endif
}

static inline void
socket_set_mark (int sd, int mark)
{
#if defined(TARGET_LINUX) && HAVE_DECL_SO_MARK
  if (mark && setsockopt (sd, SOL_SOCKET, SO_MARK, &mark, sizeof (mark)) != 0)
    msg (M_WARN, "NOTE: setsockopt SO_MARK=%d failed", mark);
#endif
}

static bool
socket_set_flags (int sd, unsigned int sockflags)
{
  if (sockflags & SF_TCP_NODELAY)
    return socket_set_tcp_nodelay (sd, 1);
  else
    return true;
}

bool
link_socket_update_flags (struct link_socket *ls, unsigned int sockflags)
{
  if (ls && socket_defined (ls->sd))
    return socket_set_flags (ls->sd, ls->sockflags = sockflags);
  else
    return false;
}

void
link_socket_update_buffer_sizes (struct link_socket *ls, int rcvbuf, int sndbuf)
{
  if (ls && socket_defined (ls->sd))
    {
      ls->socket_buffer_sizes.sndbuf = sndbuf;
      ls->socket_buffer_sizes.rcvbuf = rcvbuf;
      socket_set_buffers (ls->sd, &ls->socket_buffer_sizes);
    }
}

/*
 * SOCKET INITALIZATION CODE.
 * Create a TCP/UDP socket
 */

socket_descriptor_t
create_socket_tcp (int af)
{
  socket_descriptor_t sd;

  if ((sd = socket (af, SOCK_STREAM, IPPROTO_TCP)) < 0)
    msg (M_ERR, "Cannot create TCP socket");

#ifndef WIN32 /* using SO_REUSEADDR on Windows will cause bind to succeed on port conflicts! */
  /* set SO_REUSEADDR on socket */
  {
    int on = 1;
    if (setsockopt (sd, SOL_SOCKET, SO_REUSEADDR,
		    (void *) &on, sizeof (on)) < 0)
      msg (M_ERR, "TCP: Cannot setsockopt SO_REUSEADDR on TCP socket");
  }
#endif

  return sd;
}

static socket_descriptor_t
create_socket_udp (const unsigned int flags)
{
  socket_descriptor_t sd;

  if ((sd = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    msg (M_ERR, "UDP: Cannot create UDP socket");
#if ENABLE_IP_PKTINFO
  else if (flags & SF_USE_IP_PKTINFO)
    {
      int pad = 1;
#ifdef IP_PKTINFO
      if (setsockopt (sd, SOL_IP, IP_PKTINFO,
		      (void*)&pad, sizeof(pad)) < 0)
        msg(M_ERR, "UDP: failed setsockopt for IP_PKTINFO");
#elif defined(IP_RECVDSTADDR)
      if (setsockopt (sd, IPPROTO_IP, IP_RECVDSTADDR,
		      (void*)&pad, sizeof(pad)) < 0)
        msg(M_ERR, "UDP: failed setsockopt for IP_RECVDSTADDR");
#else
#error ENABLE_IP_PKTINFO is set without IP_PKTINFO xor IP_RECVDSTADDR (fix syshead.h)
#endif
    }
#endif
  return sd;
}

static socket_descriptor_t
create_socket_udp6 (const unsigned int flags)
{
  socket_descriptor_t sd;

  if ((sd = socket (PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    msg (M_ERR, "UDP: Cannot create UDP6 socket");
#if ENABLE_IP_PKTINFO
  else if (flags & SF_USE_IP_PKTINFO)
    {
      int pad = 1;
#ifndef IPV6_RECVPKTINFO /* Some older Darwin platforms require this */
      if (setsockopt (sd, IPPROTO_IPV6, IPV6_PKTINFO,
		      (void*)&pad, sizeof(pad)) < 0)
#else
      if (setsockopt (sd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		      (void*)&pad, sizeof(pad)) < 0)
#endif
	msg(M_ERR, "UDP: failed setsockopt for IPV6_RECVPKTINFO");
    }
#endif
  return sd;
}

static void
create_socket (struct link_socket *sock)
{
  /* create socket */
  if (sock->info.proto == PROTO_UDPv4)
    {
      sock->sd = create_socket_udp (sock->sockflags);
      sock->sockflags |= SF_GETADDRINFO_DGRAM;

#ifdef ENABLE_SOCKS
      if (sock->socks_proxy)
	sock->ctrl_sd = create_socket_tcp (AF_INET);
#endif
    }
  else if (sock->info.proto == PROTO_TCPv4_SERVER
	   || sock->info.proto == PROTO_TCPv4_CLIENT)
    {
      sock->sd = create_socket_tcp (AF_INET);
    }
  else if (sock->info.proto == PROTO_TCPv6_SERVER
	   || sock->info.proto == PROTO_TCPv6_CLIENT)
    {
      sock->sd = create_socket_tcp (AF_INET6);
    }
  else if (sock->info.proto == PROTO_UDPv6)
    {
      sock->sd = create_socket_udp6 (sock->sockflags);
      sock->sockflags |= SF_GETADDRINFO_DGRAM;
    }
  else
    {
      ASSERT (0);
    }
}

/*
 * Functions used for establishing a TCP stream connection.
 */

static void
socket_do_listen (socket_descriptor_t sd,
		  const struct openvpn_sockaddr *local,
		  bool do_listen,
		  bool do_set_nonblock)
{
  struct gc_arena gc = gc_new ();
  if (do_listen)
    {
      msg (M_INFO, "Listening for incoming TCP connection on %s", 
	   print_sockaddr (local, &gc));
      if (listen (sd, 1))
	msg (M_ERR, "TCP: listen() failed");
    }

  /* set socket to non-blocking mode */
  if (do_set_nonblock)
    set_nonblock (sd);

  gc_free (&gc);
}

socket_descriptor_t
socket_do_accept (socket_descriptor_t sd,
		  struct link_socket_actual *act,
		  const bool nowait)
{
  /* af_addr_size WILL return 0 in this case if AFs other than AF_INET
   * are compiled because act is empty here.
   * could use getsockname() to support later remote_len check
   */
  socklen_t remote_len_af = af_addr_size(act->dest.addr.sa.sa_family);
  socklen_t remote_len = sizeof(act->dest.addr);
  socket_descriptor_t new_sd = SOCKET_UNDEFINED;

  CLEAR (*act);

#ifdef HAVE_GETPEERNAME
  if (nowait)
    {
      new_sd = getpeername (sd, &act->dest.addr.sa, &remote_len);

      if (!socket_defined (new_sd))
	msg (D_LINK_ERRORS | M_ERRNO, "TCP: getpeername() failed");
      else
	new_sd = sd;
    }
#else
  if (nowait)
    msg (M_WARN, "TCP: this OS does not provide the getpeername() function");
#endif
  else
    {
      new_sd = accept (sd, &act->dest.addr.sa, &remote_len);
    }

#if 0 /* For debugging only, test the effect of accept() failures */
 {
   static int foo = 0;
   ++foo;
   if (foo & 1)
     new_sd = -1;
 }
#endif

  if (!socket_defined (new_sd))
    {
      msg (D_LINK_ERRORS | M_ERRNO, "TCP: accept(%d) failed", sd);
    }
  /* only valid if we have remote_len_af!=0 */
  else if (remote_len_af && remote_len != remote_len_af)
    {
      msg (D_LINK_ERRORS, "TCP: Received strange incoming connection with unknown address length=%d", remote_len);
      openvpn_close_socket (new_sd);
      new_sd = SOCKET_UNDEFINED;
    }
  return new_sd;
}

static void
tcp_connection_established (const struct link_socket_actual *act)
{
  struct gc_arena gc = gc_new ();
  msg (M_INFO, "TCP connection established with %s", 
       print_link_socket_actual (act, &gc));
  gc_free (&gc);
}

static int
socket_listen_accept (socket_descriptor_t sd,
		      struct link_socket_actual *act,
		      const char *remote_dynamic,
		      bool *remote_changed,
		      const struct openvpn_sockaddr *local,
		      bool do_listen,
		      bool nowait,
		      volatile int *signal_received)
{
  struct gc_arena gc = gc_new ();
  /* struct openvpn_sockaddr *remote = &act->dest; */
  struct openvpn_sockaddr remote_verify = act->dest;
  int new_sd = SOCKET_UNDEFINED;

  CLEAR (*act);
  socket_do_listen (sd, local, do_listen, true);

  while (true)
    {
      int status;
      fd_set reads;
      struct timeval tv;

      FD_ZERO (&reads);
      FD_SET (sd, &reads);
      tv.tv_sec = 0;
      tv.tv_usec = 0;

      status = select (sd + 1, &reads, NULL, NULL, &tv);

      get_signal (signal_received);
      if (*signal_received)
	{
	  gc_free (&gc);
	  return sd;
	}

      if (status < 0)
	msg (D_LINK_ERRORS | M_ERRNO, "TCP: select() failed");

      if (status <= 0)
	{
	  openvpn_sleep (1);
	  continue;
	}

      new_sd = socket_do_accept (sd, act, nowait);

      if (socket_defined (new_sd))
	{
	  update_remote (remote_dynamic, &remote_verify, remote_changed, 0);
	  if (addr_defined (&remote_verify)
	      && !addr_match (&remote_verify, &act->dest))
	    {
	      msg (M_WARN,
		   "TCP NOTE: Rejected connection attempt from %s due to --remote setting",
		   print_link_socket_actual (act, &gc));
	      if (openvpn_close_socket (new_sd))
		msg (M_ERR, "TCP: close socket failed (new_sd)");
	    }
	  else
	    break;
	}
      openvpn_sleep (1);
    }

  if (!nowait && openvpn_close_socket (sd))
    msg (M_ERR, "TCP: close socket failed (sd)");

  tcp_connection_established (act);

  gc_free (&gc);
  return new_sd;
}

void
socket_bind (socket_descriptor_t sd,
             struct openvpn_sockaddr *local,
	     const char *prefix)
{
  struct gc_arena gc = gc_new ();

  if (bind (sd, &local->addr.sa, af_addr_size(local->addr.sa.sa_family)))
    {
      const int errnum = openvpn_errno ();
      msg (M_FATAL, "%s: Socket bind failed on local address %s: %s",
	   prefix,
           print_sockaddr (local, &gc),
           strerror_ts (errnum, &gc));
    }
  gc_free (&gc);
}

int
openvpn_connect (socket_descriptor_t sd,
		 struct openvpn_sockaddr *remote,
		 int connect_timeout,
		 volatile int *signal_received)
{
  int status = 0;

#ifdef CONNECT_NONBLOCK
  set_nonblock (sd);
  status = connect (sd, &remote->addr.sa, af_addr_size(remote->addr.sa.sa_family));
  if (status)
    status = openvpn_errno ();
  if (
#ifdef WIN32
    status == WSAEWOULDBLOCK
#else
    status == EINPROGRESS
#endif
  )
    {
      while (true)
	{
	  fd_set writes;
	  struct timeval tv;

	  FD_ZERO (&writes);
	  FD_SET (sd, &writes);
	  tv.tv_sec = 0;
	  tv.tv_usec = 0;

	  status = select (sd + 1, NULL, &writes, NULL, &tv);

	  if (signal_received)
	    {
	      get_signal (signal_received);
	      if (*signal_received)
		{
		  status = 0;
		  break;
		}
	    }
	  if (status < 0)
	    {
	      status = openvpn_errno ();
	      break;
	    }
	  if (status <= 0)
	    {
	      if (--connect_timeout < 0)
		{
		  status = ETIMEDOUT;
		  break;
		}
	      openvpn_sleep (1);
	      continue;
	    }

	  /* got it */
	  {
	    int val = 0;
	    socklen_t len;

	    len = sizeof (val);
	    if (getsockopt (sd, SOL_SOCKET, SO_ERROR, (void *) &val, &len) == 0
		&& len == sizeof (val))
	      status = val;
	    else
	      status = openvpn_errno ();
	    break;
	  }
	}
    }
#else
  status = connect (sd, &remote->addr.sa, af_addr_size(remote->addr.sa.sa_family));
  if (status)
    status = openvpn_errno ();
#endif

  return status;
}

void
socket_connect (socket_descriptor_t *sd,
                struct openvpn_sockaddr *local,
                bool bind_local,
		struct openvpn_sockaddr *remote,
		const bool connection_profiles_defined,
		const char *remote_dynamic,
		bool *remote_changed,
		const int connect_retry_seconds,
		const int connect_timeout,
		const int connect_retry_max,
		const unsigned int sockflags,
		volatile int *signal_received)
{
  struct gc_arena gc = gc_new ();
  int retry = 0;

#ifdef CONNECT_NONBLOCK
  msg (M_INFO, "Attempting to establish TCP connection with %s [nonblock]", 
       print_sockaddr (remote, &gc));
#else
  msg (M_INFO, "Attempting to establish TCP connection with %s", 
       print_sockaddr (remote, &gc));
#endif

  while (true)
    {
      int status;

#ifdef ENABLE_MANAGEMENT
      if (management)
	management_set_state (management,
			      OPENVPN_STATE_TCP_CONNECT,
			      NULL,
			      (in_addr_t)0,
			      (in_addr_t)0);
#endif

      status = openvpn_connect (*sd, remote, connect_timeout, signal_received);

      get_signal (signal_received);
      if (*signal_received)
	goto done;

      if (!status)
	break;

      msg (D_LINK_ERRORS,
	   "TCP: connect to %s failed, will try again in %d seconds: %s",
	   print_sockaddr (remote, &gc),
	   connect_retry_seconds,
	   strerror_ts (status, &gc));

      gc_reset (&gc);

      openvpn_close_socket (*sd);
      *sd = SOCKET_UNDEFINED;

      if ((connect_retry_max > 0 && ++retry >= connect_retry_max) || connection_profiles_defined)
	{
	  *signal_received = SIGUSR1;
	  goto done;
	}

      openvpn_sleep (connect_retry_seconds);

      get_signal (signal_received);
      if (*signal_received)
	goto done;

	*sd = create_socket_tcp (local->addr.sa.sa_family);

      if (bind_local)
        socket_bind (*sd, local, "TCP Client");
      update_remote (remote_dynamic, remote, remote_changed, sockflags);
    }

  msg (M_INFO, "TCP connection established with %s", 
       print_sockaddr (remote, &gc));

 done:
  gc_free (&gc);
}

/* For stream protocols, allocate a buffer to build up packet.
   Called after frame has been finalized. */

static void
socket_frame_init (const struct frame *frame, struct link_socket *sock)
{
#ifdef WIN32
  overlapped_io_init (&sock->reads, frame, FALSE, false);
  overlapped_io_init (&sock->writes, frame, TRUE, false);
  sock->rw_handle.read = sock->reads.overlapped.hEvent;
  sock->rw_handle.write = sock->writes.overlapped.hEvent;
#endif

  if (link_socket_connection_oriented (sock))
    {
#ifdef WIN32
      stream_buf_init (&sock->stream_buf,
		       &sock->reads.buf_init,
		       sock->sockflags,
		       sock->info.proto);
#else
      alloc_buf_sock_tun (&sock->stream_buf_data,
			  frame,
			  false,
			  FRAME_HEADROOM_MARKER_READ_STREAM);

      stream_buf_init (&sock->stream_buf,
		       &sock->stream_buf_data,
		       sock->sockflags,
		       sock->info.proto);
#endif
    }
}

/*
 * Adjust frame structure based on a Path MTU value given
 * to us by the OS.
 */
void
frame_adjust_path_mtu (struct frame *frame, int pmtu, int proto)
{
  frame_set_mtu_dynamic (frame, pmtu - datagram_overhead (proto), SET_MTU_UPPER_BOUND);
}

static void
resolve_bind_local (struct link_socket *sock)
{
  struct gc_arena gc = gc_new ();

  /* resolve local address if undefined */
  if (!addr_defined (&sock->info.lsa->local))
    {
      /* may return AF_{INET|INET6} guessed from local_host */
      switch(addr_guess_family(sock->info.proto, sock->local_host))
	{
	case AF_INET:
	  sock->info.lsa->local.addr.in4.sin_family = AF_INET;
	  sock->info.lsa->local.addr.in4.sin_addr.s_addr =
	    (sock->local_host ? getaddr (GETADDR_RESOLVE | GETADDR_WARN_ON_SIGNAL | GETADDR_FATAL,
					 sock->local_host,
					 0,
					 NULL,
					 NULL)
	     : htonl (INADDR_ANY));
	  sock->info.lsa->local.addr.in4.sin_port = htons (sock->local_port);
	  break;
	case AF_INET6:
	    {
	      int status;
	      int err;
	      CLEAR(sock->info.lsa->local.addr.in6);
	      if (sock->local_host)
		{
		  struct addrinfo *ai;

		  status = openvpn_getaddrinfo(GETADDR_RESOLVE | GETADDR_WARN_ON_SIGNAL | GETADDR_FATAL,
									   sock->local_host, 0, NULL, AF_INET6, &ai);
		  if(status ==0) {
			  sock->info.lsa->local.addr.in6 = *((struct sockaddr_in6*)(ai->ai_addr));
			  freeaddrinfo(ai);
		  }
		}
	      else
		{
		  sock->info.lsa->local.addr.in6.sin6_family = AF_INET6;
		  sock->info.lsa->local.addr.in6.sin6_addr = in6addr_any;
		  status = 0;
		}
	      if (!status == 0)
		{
		  msg (M_FATAL, "getaddr6() failed for local \"%s\": %s",
		       sock->local_host,
		       gai_strerror(err));
		}
	      sock->info.lsa->local.addr.in6.sin6_port = htons (sock->local_port);
	    }
	  break;
	}
    }
  
  /* bind to local address/port */
  if (sock->bind_local)
    {
#ifdef ENABLE_SOCKS
      if (sock->socks_proxy && sock->info.proto == PROTO_UDPv4)
          socket_bind (sock->ctrl_sd, &sock->info.lsa->local, "SOCKS");
      else
#endif
          socket_bind (sock->sd, &sock->info.lsa->local, "TCP/UDP");
    }
  gc_free (&gc);
}

static void
resolve_remote (struct link_socket *sock,
		int phase,
		const char **remote_dynamic,
		volatile int *signal_received)
{
  struct gc_arena gc = gc_new ();
  int af;

  if (!sock->did_resolve_remote)
    {
      /* resolve remote address if undefined */
      if (!addr_defined (&sock->info.lsa->remote))
	{
          af = addr_guess_family(sock->info.proto, sock->remote_host);
          switch(af)
            {
              case AF_INET:
                sock->info.lsa->remote.addr.in4.sin_family = AF_INET;
                sock->info.lsa->remote.addr.in4.sin_addr.s_addr = 0;
                break;
              case AF_INET6:
                CLEAR(sock->info.lsa->remote.addr.in6);
                sock->info.lsa->remote.addr.in6.sin6_family = AF_INET6;
                sock->info.lsa->remote.addr.in6.sin6_addr = in6addr_any;
                break;
            }

	  if (sock->remote_host)
	    {
	      unsigned int flags = sf2gaf(GETADDR_RESOLVE|GETADDR_UPDATE_MANAGEMENT_STATE, sock->sockflags);
	      int retry = 0;
	      int status = -1;

	      if (sock->connection_profiles_defined && sock->resolve_retry_seconds == RESOLV_RETRY_INFINITE)
		{
		  if (phase == 2)
		    flags |= (GETADDR_TRY_ONCE | GETADDR_FATAL);
		  retry = 0;
		}
	      else if (phase == 1)
		{
		  if (sock->resolve_retry_seconds)
		    {
		      retry = 0;
		    }
		  else
		    {
		      flags |= (GETADDR_FATAL | GETADDR_MENTION_RESOLVE_RETRY);
		      retry = 0;
		    }
		}
	      else if (phase == 2)
		{
		  if (sock->resolve_retry_seconds)
		    {
		      flags |= GETADDR_FATAL;
		      retry = sock->resolve_retry_seconds;
		    }
		  else
		    {
		      ASSERT (0);
		    }
		}
	      else
		{
		  ASSERT (0);
		}

		  struct addrinfo* ai;
		  /* Temporary fix, this need to be changed for dual stack */
		  status = openvpn_getaddrinfo(flags, sock->remote_host, retry,
											  signal_received, af, &ai);
		  if(status == 0) {
			  sock->info.lsa->remote.addr.in6 = *((struct sockaddr_in6*)(ai->ai_addr));
			  freeaddrinfo(ai);

			  dmsg (D_SOCKET_DEBUG, "RESOLVE_REMOTE flags=0x%04x phase=%d rrs=%d sig=%d status=%d",
					flags,
					phase,
					retry,
					signal_received ? *signal_received : -1,
					status);
		  }
	      if (signal_received)
		{
		  if (*signal_received)
		    goto done;
		}
	      if (status!=0)
		{
		  if (signal_received)
		    *signal_received = SIGUSR1;
		  goto done;
		}
	    }
          switch(af)
            {
              case AF_INET:
                sock->info.lsa->remote.addr.in4.sin_port = htons (sock->remote_port);
                break;
              case AF_INET6:
                sock->info.lsa->remote.addr.in6.sin6_port = htons (sock->remote_port);
                break;
            }
	}
  
      /* should we re-use previous active remote address? */
      if (link_socket_actual_defined (&sock->info.lsa->actual))
	{
	  msg (M_INFO, "TCP/UDP: Preserving recently used remote address: %s",
	       print_link_socket_actual (&sock->info.lsa->actual, &gc));
	  if (remote_dynamic)
	    *remote_dynamic = NULL;
	}
      else
	{
	  CLEAR (sock->info.lsa->actual);
	  sock->info.lsa->actual.dest = sock->info.lsa->remote;
	}

      /* remember that we finished */
      sock->did_resolve_remote = true;
    }

 done:
  gc_free (&gc);
}

struct link_socket *
link_socket_new (void)
{
  struct link_socket *sock;

  ALLOC_OBJ_CLEAR (sock, struct link_socket);
  sock->sd = SOCKET_UNDEFINED;
#ifdef ENABLE_SOCKS
  sock->ctrl_sd = SOCKET_UNDEFINED;
#endif
  return sock;
}

/* bind socket if necessary */
void
link_socket_init_phase1 (struct link_socket *sock,
			 const bool connection_profiles_defined,
			 const char *local_host,
			 int local_port,
			 const char *remote_host,
			 int remote_port,
			 int proto,
			 int mode,
			 const struct link_socket *accept_from,
#ifdef ENABLE_HTTP_PROXY
			 struct http_proxy_info *http_proxy,
#endif
#ifdef ENABLE_SOCKS
			 struct socks_proxy_info *socks_proxy,
#endif
#ifdef ENABLE_DEBUG
			 int gremlin,
#endif
			 bool bind_local,
			 bool remote_float,
			 int inetd,
			 struct link_socket_addr *lsa,
			 const char *ipchange_command,
			 const struct plugin_list *plugins,
			 int resolve_retry_seconds,
			 int connect_retry_seconds,
			 int connect_timeout,
			 int connect_retry_max,
			 int mtu_discover_type,
			 int rcvbuf,
			 int sndbuf,
			 int mark,
			 unsigned int sockflags)
{
  ASSERT (sock);

  sock->connection_profiles_defined = connection_profiles_defined;

  sock->local_host = local_host;
  sock->local_port = local_port;
  sock->remote_host = remote_host;
  sock->remote_port = remote_port;

#ifdef ENABLE_HTTP_PROXY
  sock->http_proxy = http_proxy;
#endif

#ifdef ENABLE_SOCKS
  sock->socks_proxy = socks_proxy;
#endif

  sock->bind_local = bind_local;
  sock->inetd = inetd;
  sock->resolve_retry_seconds = resolve_retry_seconds;
  sock->connect_retry_seconds = connect_retry_seconds;
  sock->connect_timeout = connect_timeout;
  sock->connect_retry_max = connect_retry_max;
  sock->mtu_discover_type = mtu_discover_type;

#ifdef ENABLE_DEBUG
  sock->gremlin = gremlin;
#endif

  sock->socket_buffer_sizes.rcvbuf = rcvbuf;
  sock->socket_buffer_sizes.sndbuf = sndbuf;

  sock->sockflags = sockflags;

  sock->info.proto = proto;
  sock->info.remote_float = remote_float;
  sock->info.lsa = lsa;
  sock->info.ipchange_command = ipchange_command;
  sock->info.plugins = plugins;

  sock->mode = mode;
  if (mode == LS_MODE_TCP_ACCEPT_FROM)
    {
      ASSERT (accept_from);
      ASSERT (sock->info.proto == PROTO_TCPv4_SERVER
	      || sock->info.proto == PROTO_TCPv6_SERVER
	     );
      ASSERT (!sock->inetd);
      sock->sd = accept_from->sd;
    }

  if (false)
    ;
#ifdef ENABLE_HTTP_PROXY
  /* are we running in HTTP proxy mode? */
  else if (sock->http_proxy)
    {
      ASSERT (sock->info.proto == PROTO_TCPv4_CLIENT);
      ASSERT (!sock->inetd);

      /* the proxy server */
      sock->remote_host = http_proxy->options.server;
      sock->remote_port = http_proxy->options.port;

      /* the OpenVPN server we will use the proxy to connect to */
      sock->proxy_dest_host = remote_host;
      sock->proxy_dest_port = remote_port;
    }
#endif
#ifdef ENABLE_SOCKS
  /* or in Socks proxy mode? */
  else if (sock->socks_proxy)
    {
      ASSERT (sock->info.proto == PROTO_TCPv4_CLIENT || sock->info.proto == PROTO_UDPv4);
      ASSERT (!sock->inetd);

      /* the proxy server */
      sock->remote_host = socks_proxy->server;
      sock->remote_port = socks_proxy->port;

      /* the OpenVPN server we will use the proxy to connect to */
      sock->proxy_dest_host = remote_host;
      sock->proxy_dest_port = remote_port;
    }
#endif
  else
    {
      sock->remote_host = remote_host;
      sock->remote_port = remote_port;
    }

  /* bind behavior for TCP server vs. client */
  if (sock->info.proto == PROTO_TCPv4_SERVER)
    {
      if (sock->mode == LS_MODE_TCP_ACCEPT_FROM)
	sock->bind_local = false;
      else
	sock->bind_local = true;
    }

  /* were we started by inetd or xinetd? */
  if (sock->inetd)
    {
      ASSERT (sock->info.proto != PROTO_TCPv4_CLIENT
	      && sock->info.proto != PROTO_TCPv6_CLIENT);
      ASSERT (socket_defined (inetd_socket_descriptor));
      sock->sd = inetd_socket_descriptor;
    }
  else if (mode != LS_MODE_TCP_ACCEPT_FROM)
    {
      create_socket (sock);

      /* set socket buffers based on --sndbuf and --rcvbuf options */
      socket_set_buffers (sock->sd, &sock->socket_buffer_sizes);

      /* set socket to --mark packets with given value */
      socket_set_mark (sock->sd, mark);

      resolve_bind_local (sock);
      resolve_remote (sock, 1, NULL, NULL);
    }
}

/* finalize socket initialization */
void
link_socket_init_phase2 (struct link_socket *sock,
			 const struct frame *frame,
			 volatile int *signal_received)
{
  struct gc_arena gc = gc_new ();
  const char *remote_dynamic = NULL;
  bool remote_changed = false;
  int sig_save = 0;

  ASSERT (sock);

  if (signal_received && *signal_received)
    {
      sig_save = *signal_received;
      *signal_received = 0;
    }

  /* initialize buffers */
  socket_frame_init (frame, sock);

  /*
   * Pass a remote name to connect/accept so that
   * they can test for dynamic IP address changes
   * and throw a SIGUSR1 if appropriate.
   */
  if (sock->resolve_retry_seconds)
    remote_dynamic = sock->remote_host;

  /* were we started by inetd or xinetd? */
  if (sock->inetd)
    {
      if (sock->info.proto == PROTO_TCPv4_SERVER
	  || sock->info.proto == PROTO_TCPv6_SERVER) {
	/* AF_INET as default (and fallback) for inetd */
	sock->info.lsa->actual.dest.addr.sa.sa_family = AF_INET;
#ifdef HAVE_GETSOCKNAME
	  {
	    /* inetd: hint family type for dest = local's */
	    struct openvpn_sockaddr local_addr;
	    socklen_t addrlen = sizeof(local_addr);
	    if (getsockname (sock->sd, (struct sockaddr *)&local_addr, &addrlen) == 0) {
	      sock->info.lsa->actual.dest.addr.sa.sa_family = local_addr.addr.sa.sa_family;
	      dmsg (D_SOCKET_DEBUG, "inetd(%s): using sa_family=%d from getsockname(%d)",
		    proto2ascii(sock->info.proto, false), local_addr.addr.sa.sa_family,
		    sock->sd);
	    } else
	      msg (M_WARN, "inetd(%s): getsockname(%d) failed, using AF_INET",
		   proto2ascii(sock->info.proto, false), sock->sd);
	  }
#else
	msg (M_WARN, "inetd(%s): this OS does not provide the getsockname() "
	     "function, using AF_INET",
	     proto2ascii(sock->info.proto, false));
#endif
	sock->sd =
	  socket_listen_accept (sock->sd,
				&sock->info.lsa->actual,
				remote_dynamic,
				&remote_changed,
				&sock->info.lsa->local,
				false,
				sock->inetd == INETD_NOWAIT,
				signal_received);
      }
      ASSERT (!remote_changed);
      if (*signal_received)
	goto done;
    }
  else
    {
      resolve_remote (sock, 2, &remote_dynamic, signal_received);

      if (*signal_received)
	goto done;

      /* TCP client/server */
      if (sock->info.proto == PROTO_TCPv4_SERVER
	  ||sock->info.proto == PROTO_TCPv6_SERVER)
	{
	  switch (sock->mode)
	    {
	    case LS_MODE_DEFAULT:
	      sock->sd = socket_listen_accept (sock->sd,
					       &sock->info.lsa->actual,
					       remote_dynamic,
					       &remote_changed,
					       &sock->info.lsa->local,
					       true,
					       false,
					       signal_received);
	      break;
	    case LS_MODE_TCP_LISTEN:
	      socket_do_listen (sock->sd,
				&sock->info.lsa->local,
				true,
				false);
	      break;
	    case LS_MODE_TCP_ACCEPT_FROM:
	      sock->sd = socket_do_accept (sock->sd,
					   &sock->info.lsa->actual,
					   false);
	      if (!socket_defined (sock->sd))
		{
		  *signal_received = SIGTERM;
		  goto done;
		}
	      tcp_connection_established (&sock->info.lsa->actual);
	      break;
	    default:
	      ASSERT (0);
	    }
	}
      else if (sock->info.proto == PROTO_TCPv4_CLIENT
	       ||sock->info.proto == PROTO_TCPv6_CLIENT)
	{

#ifdef GENERAL_PROXY_SUPPORT
	  bool proxy_retry = false;
#else
	  const bool proxy_retry = false;
#endif
	  do {
	    socket_connect (&sock->sd,
			    &sock->info.lsa->local,
			    sock->bind_local,
			    &sock->info.lsa->actual.dest,
			    sock->connection_profiles_defined,
			    remote_dynamic,
			    &remote_changed,
			    sock->connect_retry_seconds,
			    sock->connect_timeout,
			    sock->connect_retry_max,
			    sock->sockflags,
			    signal_received);

	    if (*signal_received)
	      goto done;

	    if (false)
	      ;
#ifdef ENABLE_HTTP_PROXY
	    else if (sock->http_proxy)
	      {
		proxy_retry = establish_http_proxy_passthru (sock->http_proxy,
							     sock->sd,
							     sock->proxy_dest_host,
							     sock->proxy_dest_port,
							     &sock->stream_buf.residual,
							     signal_received);
	      }
#endif
#ifdef ENABLE_SOCKS
	    else if (sock->socks_proxy)
	      {
		establish_socks_proxy_passthru (sock->socks_proxy,
						sock->sd,
						sock->proxy_dest_host,
						sock->proxy_dest_port,
						signal_received);
	      }
#endif
	    if (proxy_retry)
	      {
		openvpn_close_socket (sock->sd);
		sock->sd = create_socket_tcp (AF_INET);
	      }
	  } while (proxy_retry);
	}
#ifdef ENABLE_SOCKS
      else if (sock->info.proto == PROTO_UDPv4 && sock->socks_proxy)
	{
	  socket_connect (&sock->ctrl_sd,
                          &sock->info.lsa->local,
                          sock->bind_local,
			  &sock->info.lsa->actual.dest,
			  sock->connection_profiles_defined,
			  remote_dynamic,
			  &remote_changed,
			  sock->connect_retry_seconds,
			  sock->connect_timeout,
			  sock->connect_retry_max,
			  sock->sockflags,
			  signal_received);

	  if (*signal_received)
	    goto done;

	  establish_socks_proxy_udpassoc (sock->socks_proxy,
					  sock->ctrl_sd,
					  sock->sd,
					  &sock->socks_relay.dest,
					  signal_received);

	  if (*signal_received)
	    goto done;

	  sock->remote_host = sock->proxy_dest_host;
	  sock->remote_port = sock->proxy_dest_port;
	  sock->did_resolve_remote = false;

	  addr_zero_host(&sock->info.lsa->actual.dest);
	  addr_zero_host(&sock->info.lsa->remote);

	  resolve_remote (sock, 1, NULL, signal_received);

	  if (*signal_received)
	    goto done;
	}
#endif

      if (*signal_received)
	goto done;

      if (remote_changed)
	{
	  msg (M_INFO, "TCP/UDP: Dynamic remote address changed during TCP connection establishment");
	  addr_copy_host(&sock->info.lsa->remote, &sock->info.lsa->actual.dest);
	}
    }

  /* set misc socket parameters */
  socket_set_flags (sock->sd, sock->sockflags);

  /* set socket to non-blocking mode */
  set_nonblock (sock->sd);

  /* set socket file descriptor to not pass across execs, so that
     scripts don't have access to it */
  set_cloexec (sock->sd);

#ifdef ENABLE_SOCKS
  if (socket_defined (sock->ctrl_sd))
    set_cloexec (sock->ctrl_sd);
#endif

  /* set Path MTU discovery options on the socket */
  set_mtu_discover_type (sock->sd, sock->mtu_discover_type);

#if EXTENDED_SOCKET_ERROR_CAPABILITY
  /* if the OS supports it, enable extended error passing on the socket */
  set_sock_extended_error_passing (sock->sd);
#endif

  /* print local address */
  {
    const int msglevel = (sock->mode == LS_MODE_TCP_ACCEPT_FROM) ? D_INIT_MEDIUM : M_INFO;

    if (sock->inetd)
      msg (msglevel, "%s link local: [inetd]", proto2ascii (sock->info.proto, true));
    else
      msg (msglevel, "%s link local%s: %s",
	   proto2ascii (sock->info.proto, true),
	   (sock->bind_local ? " (bound)" : ""),
	   print_sockaddr_ex (&sock->info.lsa->local, ":", sock->bind_local ? PS_SHOW_PORT : 0, &gc));

    /* print active remote address */
    msg (msglevel, "%s link remote: %s",
	 proto2ascii (sock->info.proto, true),
	 print_link_socket_actual_ex (&sock->info.lsa->actual,
				      ":",
				      PS_SHOW_PORT_IF_DEFINED,
				      &gc));
  }

 done:
  if (sig_save && signal_received)
    {
      if (!*signal_received)
	*signal_received = sig_save;
    }
  gc_free (&gc);
}

void
link_socket_close (struct link_socket *sock)
{
  if (sock)
    {
#ifdef ENABLE_DEBUG
      const int gremlin = GREMLIN_CONNECTION_FLOOD_LEVEL (sock->gremlin);
#else
      const int gremlin = 0;
#endif

      if (socket_defined (sock->sd))
	{
#ifdef WIN32
	  close_net_event_win32 (&sock->listen_handle, sock->sd, 0);
#endif
	  if (!gremlin)
	    {
	      msg (D_LOW, "TCP/UDP: Closing socket");
	      if (openvpn_close_socket (sock->sd))
		msg (M_WARN | M_ERRNO, "TCP/UDP: Close Socket failed");
	    }
	  sock->sd = SOCKET_UNDEFINED;
#ifdef WIN32
	  if (!gremlin)
	    {
	      overlapped_io_close (&sock->reads);
	      overlapped_io_close (&sock->writes);
	    }
#endif
	}

#ifdef ENABLE_SOCKS
      if (socket_defined (sock->ctrl_sd))
	{
	  if (openvpn_close_socket (sock->ctrl_sd))
	    msg (M_WARN | M_ERRNO, "TCP/UDP: Close Socket (ctrl_sd) failed");
	  sock->ctrl_sd = SOCKET_UNDEFINED;
	}
#endif

      stream_buf_close (&sock->stream_buf);
      free_buf (&sock->stream_buf_data);
      if (!gremlin)
	free (sock);
    }
}

/* for stream protocols, allow for packet length prefix */
void
socket_adjust_frame_parameters (struct frame *frame, int proto)
{
  if (link_socket_proto_connection_oriented (proto))
    frame_add_to_extra_frame (frame, sizeof (packet_size_type));
}

void
setenv_trusted (struct env_set *es, const struct link_socket_info *info)
{
  setenv_link_socket_actual (es, "trusted", &info->lsa->actual, SA_IP_PORT);
}

static void
ipchange_fmt (const bool include_cmd, struct argv *argv, const struct link_socket_info *info, struct gc_arena *gc)
{
  const char *ip = print_sockaddr_ex (&info->lsa->actual.dest, NULL, 0, gc);
  const char *port = print_sockaddr_ex (&info->lsa->actual.dest, NULL, PS_DONT_SHOW_ADDR|PS_SHOW_PORT, gc);
  if (include_cmd)
    argv_printf (argv, "%sc %s %s",
		 info->ipchange_command,
		 ip,
		 port);
  else
    argv_printf (argv, "%s %s",
		 ip,
		 port);
}

void
link_socket_connection_initiated (const struct buffer *buf,
				  struct link_socket_info *info,
				  const struct link_socket_actual *act,
				  const char *common_name,
				  struct env_set *es)
{
  struct gc_arena gc = gc_new ();
  
  info->lsa->actual = *act; /* Note: skip this line for --force-dest */
  setenv_trusted (es, info);
  info->connection_established = true;

  /* Print connection initiated message, with common name if available */
  {
    struct buffer out = alloc_buf_gc (256, &gc);
    if (common_name)
      buf_printf (&out, "[%s] ", common_name);
    buf_printf (&out, "Peer Connection Initiated with %s", print_link_socket_actual (&info->lsa->actual, &gc));
    msg (M_INFO, "%s", BSTR (&out));
  }

  /* set environmental vars */
  setenv_str (es, "common_name", common_name);

  /* Process --ipchange plugin */
  if (plugin_defined (info->plugins, OPENVPN_PLUGIN_IPCHANGE))
    {
      struct argv argv = argv_new ();
      ipchange_fmt (false, &argv, info, &gc);
      if (plugin_call (info->plugins, OPENVPN_PLUGIN_IPCHANGE, &argv, NULL, es) != OPENVPN_PLUGIN_FUNC_SUCCESS)
	msg (M_WARN, "WARNING: ipchange plugin call failed");
      argv_reset (&argv);
    }

  /* Process --ipchange option */
  if (info->ipchange_command)
    {
      struct argv argv = argv_new ();
      setenv_str (es, "script_type", "ipchange");
      ipchange_fmt (true, &argv, info, &gc);
      openvpn_run_script (&argv, es, 0, "--ipchange");
      argv_reset (&argv);
    }

  gc_free (&gc);
}

void
link_socket_bad_incoming_addr (struct buffer *buf,
			       const struct link_socket_info *info,
			       const struct link_socket_actual *from_addr)
{
  struct gc_arena gc = gc_new ();

  switch(from_addr->dest.addr.sa.sa_family)
    {
    case AF_INET:
    case AF_INET6:
      msg (D_LINK_ERRORS,
	   "TCP/UDP: Incoming packet rejected from %s[%d], expected peer address: %s (allow this incoming source address/port by removing --remote or adding --float)",
	   print_link_socket_actual (from_addr, &gc),
	   (int)from_addr->dest.addr.sa.sa_family,
	   print_sockaddr (&info->lsa->remote, &gc));
      break;
    }
  buf->len = 0;
  gc_free (&gc);
}

void
link_socket_bad_outgoing_addr (void)
{
  dmsg (D_READ_WRITE, "TCP/UDP: No outgoing address to send packet");
}

in_addr_t
link_socket_current_remote (const struct link_socket_info *info)
{
  const struct link_socket_addr *lsa = info->lsa;

/* 
 * This logic supports "redirect-gateway" semantic, which 
 * makes sense only for PF_INET routes over PF_INET endpoints
 *
 * Maybe in the future consider PF_INET6 endpoints also ...
 * by now just ignore it
 *
 */
  if (lsa->actual.dest.addr.sa.sa_family != AF_INET)
    return IPV4_INVALID_ADDR;

  if (link_socket_actual_defined (&lsa->actual))
    return ntohl (lsa->actual.dest.addr.in4.sin_addr.s_addr);
  else if (addr_defined (&lsa->remote))
    return ntohl (lsa->remote.addr.in4.sin_addr.s_addr);
  else
    return 0;
}

/*
 * Return a status string describing socket state.
 */
const char *
socket_stat (const struct link_socket *s, unsigned int rwflags, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (64, gc);
  if (s)
    {
      if (rwflags & EVENT_READ)
	{
	  buf_printf (&out, "S%s",
		      (s->rwflags_debug & EVENT_READ) ? "R" : "r");
#ifdef WIN32
	  buf_printf (&out, "%s",
		      overlapped_io_state_ascii (&s->reads));
#endif
	}
      if (rwflags & EVENT_WRITE)
	{
	  buf_printf (&out, "S%s",
		      (s->rwflags_debug & EVENT_WRITE) ? "W" : "w");
#ifdef WIN32
	  buf_printf (&out, "%s",
		      overlapped_io_state_ascii (&s->writes));
#endif
	}
    }
  else
    {
      buf_printf (&out, "S?");
    }
  return BSTR (&out);
}

/*
 * Stream buffer functions, used to packetize a TCP
 * stream connection.
 */

static inline void
stream_buf_reset (struct stream_buf *sb)
{
  dmsg (D_STREAM_DEBUG, "STREAM: RESET");
  sb->residual_fully_formed = false;
  sb->buf = sb->buf_init;
  buf_reset (&sb->next);
  sb->len = -1;
}

void
stream_buf_init (struct stream_buf *sb,
		 struct buffer *buf,
		 const unsigned int sockflags,
		 const int proto)
{
  sb->buf_init = *buf;
  sb->maxlen = sb->buf_init.len;
  sb->buf_init.len = 0;
  sb->residual = alloc_buf (sb->maxlen);
  sb->error = false;
#if PORT_SHARE
  sb->port_share_state = ((sockflags & SF_PORT_SHARE) && (proto == PROTO_TCPv4_SERVER))
    ? PS_ENABLED
    : PS_DISABLED;
#endif
  stream_buf_reset (sb);

  dmsg (D_STREAM_DEBUG, "STREAM: INIT maxlen=%d", sb->maxlen);
}

static inline void
stream_buf_set_next (struct stream_buf *sb)
{
  /* set up 'next' for next i/o read */
  sb->next = sb->buf;
  sb->next.offset = sb->buf.offset + sb->buf.len;
  sb->next.len = (sb->len >= 0 ? sb->len : sb->maxlen) - sb->buf.len;
  dmsg (D_STREAM_DEBUG, "STREAM: SET NEXT, buf=[%d,%d] next=[%d,%d] len=%d maxlen=%d",
       sb->buf.offset, sb->buf.len,
       sb->next.offset, sb->next.len,
       sb->len, sb->maxlen);
  ASSERT (sb->next.len > 0);
  ASSERT (buf_safe (&sb->buf, sb->next.len));
}

static inline void
stream_buf_get_final (struct stream_buf *sb, struct buffer *buf)
{
  dmsg (D_STREAM_DEBUG, "STREAM: GET FINAL len=%d",
       buf_defined (&sb->buf) ? sb->buf.len : -1);
  ASSERT (buf_defined (&sb->buf));
  *buf = sb->buf;
}

static inline void
stream_buf_get_next (struct stream_buf *sb, struct buffer *buf)
{
  dmsg (D_STREAM_DEBUG, "STREAM: GET NEXT len=%d",
       buf_defined (&sb->next) ? sb->next.len : -1);
  ASSERT (buf_defined (&sb->next));
  *buf = sb->next;
}

bool
stream_buf_read_setup_dowork (struct link_socket* sock)
{
  if (sock->stream_buf.residual.len && !sock->stream_buf.residual_fully_formed)
    {
      ASSERT (buf_copy (&sock->stream_buf.buf, &sock->stream_buf.residual));
      ASSERT (buf_init (&sock->stream_buf.residual, 0));
      sock->stream_buf.residual_fully_formed = stream_buf_added (&sock->stream_buf, 0);
      dmsg (D_STREAM_DEBUG, "STREAM: RESIDUAL FULLY FORMED [%s], len=%d",
	   sock->stream_buf.residual_fully_formed ? "YES" : "NO",
	   sock->stream_buf.residual.len);
    }

  if (!sock->stream_buf.residual_fully_formed)
    stream_buf_set_next (&sock->stream_buf);
  return !sock->stream_buf.residual_fully_formed;
}

bool
stream_buf_added (struct stream_buf *sb,
		  int length_added)
{
  dmsg (D_STREAM_DEBUG, "STREAM: ADD length_added=%d", length_added);
  if (length_added > 0)
    sb->buf.len += length_added;

  /* if length unknown, see if we can get the length prefix from
     the head of the buffer */
  if (sb->len < 0 && sb->buf.len >= (int) sizeof (packet_size_type))
    {
      packet_size_type net_size;

#if PORT_SHARE
      if (sb->port_share_state == PS_ENABLED)
	{
	  if (!is_openvpn_protocol (&sb->buf))
	    {
	      msg (D_STREAM_ERRORS, "Non-OpenVPN client protocol detected");
	      sb->port_share_state = PS_FOREIGN;
	      sb->error = true;
	      return false;
	    }
	  else
	    sb->port_share_state = PS_DISABLED;
	}
#endif

      ASSERT (buf_read (&sb->buf, &net_size, sizeof (net_size)));
      sb->len = ntohps (net_size);

      if (sb->len < 1 || sb->len > sb->maxlen)
	{
	  msg (M_WARN, "WARNING: Bad encapsulated packet length from peer (%d), which must be > 0 and <= %d -- please ensure that --tun-mtu or --link-mtu is equal on both peers -- this condition could also indicate a possible active attack on the TCP link -- [Attempting restart...]", sb->len, sb->maxlen);
	  stream_buf_reset (sb);
	  sb->error = true;
	  return false;
	}
    }

  /* is our incoming packet fully read? */
  if (sb->len > 0 && sb->buf.len >= sb->len)
    {
      /* save any residual data that's part of the next packet */
      ASSERT (buf_init (&sb->residual, 0));
      if (sb->buf.len > sb->len)
	  ASSERT (buf_copy_excess (&sb->residual, &sb->buf, sb->len));
      dmsg (D_STREAM_DEBUG, "STREAM: ADD returned TRUE, buf_len=%d, residual_len=%d",
	   BLEN (&sb->buf),
	   BLEN (&sb->residual));
      return true;
    }
  else
    {
      dmsg (D_STREAM_DEBUG, "STREAM: ADD returned FALSE (have=%d need=%d)", sb->buf.len, sb->len);
      stream_buf_set_next (sb);
      return false;
    }
}

void
stream_buf_close (struct stream_buf* sb)
{
  free_buf (&sb->residual);
}

/*
 * The listen event is a special event whose sole purpose is
 * to tell us that there's a new incoming connection on a
 * TCP socket, for use in server mode.
 */
event_t
socket_listen_event_handle (struct link_socket *s)
{
#ifdef WIN32
  if (!defined_net_event_win32 (&s->listen_handle))
    init_net_event_win32 (&s->listen_handle, FD_ACCEPT, s->sd, 0);
  return &s->listen_handle;
#else
  return s->sd;
#endif
}

/*
 * Format IP addresses in ascii
 */

const char *
print_sockaddr (const struct openvpn_sockaddr *addr, struct gc_arena *gc)
{
  return print_sockaddr_ex (addr, ":", PS_SHOW_PORT, gc);
}

const char *
print_sockaddr_ex (const struct openvpn_sockaddr *addr,
		   const char* separator,
		   const unsigned int flags,
		   struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (128, gc);
  bool addr_is_defined;
  addr_is_defined = addr_defined (addr);
  if (!addr_is_defined) {
    return "[undef]";
  }
  switch(addr->addr.sa.sa_family)
    {
    case AF_INET:
	{
	  const int port= ntohs (addr->addr.in4.sin_port);
	  buf_puts (&out, "[AF_INET]");

	  if (!(flags & PS_DONT_SHOW_ADDR))
	    buf_printf (&out, "%s", (addr_defined (addr) ? inet_ntoa (addr->addr.in4.sin_addr) : "[undef]"));

	  if (((flags & PS_SHOW_PORT) || (addr_defined (addr) && (flags & PS_SHOW_PORT_IF_DEFINED)))
	      && port)
	    {
	      if (separator)
		buf_printf (&out, "%s", separator);

	      buf_printf (&out, "%d", port);
	    }
	}
      break;
    case AF_INET6:
	{
	  const int port= ntohs (addr->addr.in6.sin6_port);
	  char buf[INET6_ADDRSTRLEN] = "";
	  buf_puts (&out, "[AF_INET6]");
	  if (addr_is_defined)
	    {
	      getnameinfo(&addr->addr.sa, sizeof (struct sockaddr_in6),
			  buf, sizeof (buf), NULL, 0, NI_NUMERICHOST);
	      buf_puts (&out, buf);
	    }
	  if (((flags & PS_SHOW_PORT) || (addr_is_defined && (flags & PS_SHOW_PORT_IF_DEFINED)))
	      && port)
	    {
	      if (separator)
		buf_puts (&out, separator);

	      buf_printf (&out, "%d", port);
	    }
	}
      break;
    default:
      ASSERT(0);
    }
  return BSTR (&out);
}

const char *
print_link_socket_actual (const struct link_socket_actual *act, struct gc_arena *gc)
{
  return print_link_socket_actual_ex (act, ":", PS_SHOW_PORT|PS_SHOW_PKTINFO, gc);
}

#ifndef IF_NAMESIZE
#define IF_NAMESIZE 16
#endif

const char *
print_link_socket_actual_ex (const struct link_socket_actual *act,
			     const char *separator,
			     const unsigned int flags,
			     struct gc_arena *gc)
{
  if (act)
    {
      char ifname[IF_NAMESIZE] = "[undef]";
      struct buffer out = alloc_buf_gc (128, gc);
      buf_printf (&out, "%s", print_sockaddr_ex (&act->dest, separator, flags, gc));
#if ENABLE_IP_PKTINFO
      if ((flags & PS_SHOW_PKTINFO) && addr_defined_ipi(act))
	{
	  switch(act->dest.addr.sa.sa_family)
	    {
	    case AF_INET:
		{
		  struct openvpn_sockaddr sa;
		  CLEAR (sa);
		  sa.addr.in4.sin_family = AF_INET;
#ifdef IP_PKTINFO
		  sa.addr.in4.sin_addr = act->pi.in4.ipi_spec_dst;
		  if_indextoname(act->pi.in4.ipi_ifindex, ifname);
#elif defined(IP_RECVDSTADDR)
		  sa.addr.in4.sin_addr = act->pi.in4;
		  ifname[0]=0;
#else
#error ENABLE_IP_PKTINFO is set without IP_PKTINFO xor IP_RECVDSTADDR (fix syshead.h)
#endif
		  buf_printf (&out, " (via %s%%%s)",
			      print_sockaddr_ex (&sa, separator, 0, gc),
			      ifname);
		}
	      break;
	    case AF_INET6:
		{
		  struct sockaddr_in6 sin6;
		  char buf[INET6_ADDRSTRLEN] = "[undef]";
		  CLEAR(sin6);
		  sin6.sin6_family = AF_INET6;
		  sin6.sin6_addr = act->pi.in6.ipi6_addr;
		  if_indextoname(act->pi.in6.ipi6_ifindex, ifname);
		  if (getnameinfo((struct sockaddr *)&sin6, sizeof (struct sockaddr_in6),
				  buf, sizeof (buf), NULL, 0, NI_NUMERICHOST) == 0)
		    buf_printf (&out, " (via %s%%%s)", buf, ifname);
		  else
		    buf_printf (&out, " (via [getnameinfo() err]%%%s)", ifname);
		}
	      break;
	    }
	}
#endif
      return BSTR (&out);
    }
  else
    return "[NULL]";
}

/*
 * Convert an in_addr_t in host byte order
 * to an ascii dotted quad.
 */
const char *
print_in_addr_t (in_addr_t addr, unsigned int flags, struct gc_arena *gc)
{
  struct in_addr ia;
  struct buffer out = alloc_buf_gc (64, gc);

  if (addr || !(flags & IA_EMPTY_IF_UNDEF))
    {
      CLEAR (ia);
      ia.s_addr = (flags & IA_NET_ORDER) ? addr : htonl (addr);

      buf_printf (&out, "%s", inet_ntoa (ia));
    }
  return BSTR (&out);
}

/*
 * Convert an in6_addr in host byte order
 * to an ascii representation of an IPv6 address
 */
const char *
print_in6_addr (struct in6_addr a6, unsigned int flags, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (64, gc);
  char tmp_out_buf[64];		/* inet_ntop wants pointer to buffer */

  if ( memcmp(&a6, &in6addr_any, sizeof(a6)) != 0 || 
       !(flags & IA_EMPTY_IF_UNDEF))
    {
      inet_ntop (AF_INET6, &a6, tmp_out_buf, sizeof(tmp_out_buf)-1);
      buf_printf (&out, "%s", tmp_out_buf );
    }
  return BSTR (&out);
}

#ifndef UINT8_MAX
# define UINT8_MAX 0xff
#endif

/* add some offset to an ipv6 address
 * (add in steps of 8 bits, taking overflow into next round)
 */
struct in6_addr add_in6_addr( struct in6_addr base, uint32_t add )
{
    int i;

    for( i=15; i>=0 && add > 0 ; i-- )
    {
	register int carry;
	register uint32_t h;

	h = (unsigned char) base.s6_addr[i];
	base.s6_addr[i] = (h+add) & UINT8_MAX;

	/* using explicit carry for the 8-bit additions will catch
         * 8-bit and(!) 32-bit overruns nicely
         */
	carry = ((h & 0xff)  + (add & 0xff)) >> 8;
	add = (add>>8) + carry;
    }
    return base;
}

/* set environmental variables for ip/port in *addr */
void
setenv_sockaddr (struct env_set *es, const char *name_prefix, const struct openvpn_sockaddr *addr, const unsigned int flags)
{
  char name_buf[256];

  char buf[128];
  switch(addr->addr.sa.sa_family)
    {
    case AF_INET:
      if (flags & SA_IP_PORT)
	openvpn_snprintf (name_buf, sizeof (name_buf), "%s_ip", name_prefix);
      else
	openvpn_snprintf (name_buf, sizeof (name_buf), "%s", name_prefix);

      setenv_str (es, name_buf, inet_ntoa (addr->addr.in4.sin_addr));

      if ((flags & SA_IP_PORT) && addr->addr.in4.sin_port)
	{
	  openvpn_snprintf (name_buf, sizeof (name_buf), "%s_port", name_prefix);
	  setenv_int (es, name_buf, ntohs (addr->addr.in4.sin_port));
	}
      break;
    case AF_INET6:
      openvpn_snprintf (name_buf, sizeof (name_buf), "%s_ip6", name_prefix);
      getnameinfo(&addr->addr.sa, sizeof (struct sockaddr_in6),
		  buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
      setenv_str (es, name_buf, buf);

      if ((flags & SA_IP_PORT) && addr->addr.in6.sin6_port)
	{
	  openvpn_snprintf (name_buf, sizeof (name_buf), "%s_port", name_prefix);
	  setenv_int (es, name_buf, ntohs (addr->addr.in6.sin6_port));
	}
      break;
    }
}

void
setenv_in_addr_t (struct env_set *es, const char *name_prefix, in_addr_t addr, const unsigned int flags)
{
  if (addr || !(flags & SA_SET_IF_NONZERO))
    {
      struct openvpn_sockaddr si;
      CLEAR (si);
      si.addr.in4.sin_family = AF_INET;
      si.addr.in4.sin_addr.s_addr = htonl (addr);
      setenv_sockaddr (es, name_prefix, &si, flags);
    }
}

void
setenv_link_socket_actual (struct env_set *es,
			   const char *name_prefix,
			   const struct link_socket_actual *act,
			   const unsigned int flags)
{
  setenv_sockaddr (es, name_prefix, &act->dest, flags);
}

/*
 * Convert protocol names between index and ascii form.
 */

struct proto_names {
  const char *short_form;
  const char *display_form;
  bool	is_dgram;
  bool	is_net;
  unsigned short proto_af;
};

/* Indexed by PROTO_x */
static const struct proto_names proto_names[PROTO_N] = {
  {"proto-uninitialized",        "proto-NONE",0,0, AF_UNSPEC},
  {"udp",        "UDPv4",1,1, AF_INET},
  {"tcp-server", "TCPv4_SERVER",0,1, AF_INET},
  {"tcp-client", "TCPv4_CLIENT",0,1, AF_INET},
  {"tcp",        "TCPv4",0,1, AF_INET},
  {"udp6"       ,"UDPv6",1,1, AF_INET6},
  {"tcp6-server","TCPv6_SERVER",0,1, AF_INET6},
  {"tcp6-client","TCPv6_CLIENT",0,1, AF_INET6},
  {"tcp6"       ,"TCPv6",0,1, AF_INET6},
};

bool
proto_is_net(int proto)
{
  if (proto < 0 || proto >= PROTO_N)
    ASSERT(0);
  return proto_names[proto].is_net;
}
bool
proto_is_dgram(int proto)
{
  if (proto < 0 || proto >= PROTO_N)
    ASSERT(0);
  return proto_names[proto].is_dgram;
}
bool
proto_is_udp(int proto)
{
  if (proto < 0 || proto >= PROTO_N)
    ASSERT(0);
  return proto_names[proto].is_dgram&&proto_names[proto].is_net;
}
bool
proto_is_tcp(int proto)
{
  if (proto < 0 || proto >= PROTO_N)
    ASSERT(0);
  return (!proto_names[proto].is_dgram)&&proto_names[proto].is_net;
}

unsigned short 
proto_sa_family(int proto)
{
  if (proto < 0 || proto >= PROTO_N)
    ASSERT(0);
  return proto_names[proto].proto_af;
}

int
ascii2proto (const char* proto_name)
{
  int i;
  ASSERT (PROTO_N == SIZE (proto_names));
  for (i = 0; i < PROTO_N; ++i)
    if (!strcmp (proto_name, proto_names[i].short_form))
      return i;
  return -1;
}

const char *
proto2ascii (int proto, bool display_form)
{
  ASSERT (PROTO_N == SIZE (proto_names));
  if (proto < 0 || proto >= PROTO_N)
    return "[unknown protocol]";
  else if (display_form)
    return proto_names[proto].display_form;
  else
    return proto_names[proto].short_form;
}

const char *
proto2ascii_all (struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (256, gc);
  int i;

  ASSERT (PROTO_N == SIZE (proto_names));
  for (i = 0; i < PROTO_N; ++i)
    {
      if (i)
	buf_printf(&out, " ");
      buf_printf(&out, "[%s]", proto2ascii(i, false));
    }
  return BSTR (&out);
}

int
addr_guess_family(int proto, const char *name) 
{
  unsigned short ret;
  if (proto)
    {
      return proto_sa_family(proto);	/* already stamped */
    } 
  else
    {
      struct addrinfo hints , *ai;
      int err;
      CLEAR(hints);
      hints.ai_flags = AI_NUMERICHOST;
      err = getaddrinfo(name, NULL, &hints, &ai);
      if ( 0 == err )
	{
	  ret=ai->ai_family;
	  freeaddrinfo(ai);
	  return ret;
	}
    }
  return AF_INET;	/* default */
}
const char *
addr_family_name (int af) 
{
  switch (af)
    {
    case AF_INET:  return "AF_INET";
    case AF_INET6: return "AF_INET6";
    }
  return "AF_UNSPEC";
}

/*
 * Given a local proto, return local proto
 * if !remote, or compatible remote proto
 * if remote.
 *
 * This is used for options compatibility
 * checking.
 *
 * IPv6 and IPv4 protocols are comptabile but OpenVPN
 * has always sent UDPv4, TCPv4 over the wire. Keep these
 * strings for backward compatbility
 */
int
proto_remote (int proto, bool remote)
{
  ASSERT (proto >= 0 && proto < PROTO_N);
  if (remote)
    {
      switch (proto)
      {
      case PROTO_TCPv4_SERVER: return PROTO_TCPv4_CLIENT;
      case PROTO_TCPv4_CLIENT: return PROTO_TCPv4_SERVER;
      case PROTO_TCPv6_SERVER: return PROTO_TCPv4_CLIENT;
      case PROTO_TCPv6_CLIENT: return PROTO_TCPv4_SERVER;
      case PROTO_UDPv6: return PROTO_UDPv4;
      }
    }
  else
    {
      switch (proto)
      {
      case PROTO_TCPv6_SERVER: return PROTO_TCPv4_SERVER;
      case PROTO_TCPv6_CLIENT: return PROTO_TCPv4_CLIENT;
      case PROTO_UDPv6: return PROTO_UDPv4;
      }
    }
  return proto;
}

/*
 * Bad incoming address lengths that differ from what
 * we expect are considered to be fatal errors.
 */
void
bad_address_length (int actual, int expected)
{
  msg (M_FATAL, "ERROR: received strange incoming packet with an address length of %d -- we only accept address lengths of %d.",
       actual,
       expected);
}

/*
 * Socket Read Routines
 */

int
link_socket_read_tcp (struct link_socket *sock,
		      struct buffer *buf)
{
  int len = 0;

  if (!sock->stream_buf.residual_fully_formed)
    {
#ifdef WIN32
      len = socket_finalize (sock->sd, &sock->reads, buf, NULL);
#else
      struct buffer frag;
      stream_buf_get_next (&sock->stream_buf, &frag);
      len = recv (sock->sd, BPTR (&frag), BLEN (&frag), MSG_NOSIGNAL);
#endif

      if (!len)
	sock->stream_reset = true;
      if (len <= 0)
	return buf->len = len;
    }

  if (sock->stream_buf.residual_fully_formed
      || stream_buf_added (&sock->stream_buf, len)) /* packet complete? */
    {
      stream_buf_get_final (&sock->stream_buf, buf);
      stream_buf_reset (&sock->stream_buf);
      return buf->len;
    }
  else
    return buf->len = 0; /* no error, but packet is still incomplete */
}

#ifndef WIN32

#if ENABLE_IP_PKTINFO

#pragma pack(1) /* needed to keep structure size consistent for 32 vs. 64-bit architectures */
struct openvpn_in4_pktinfo
{
  struct cmsghdr cmsghdr;
#ifdef HAVE_IN_PKTINFO
  struct in_pktinfo pi4;
#elif defined(IP_RECVDSTADDR)
  struct in_addr pi4;
#endif
};
struct openvpn_in6_pktinfo
{
  struct cmsghdr cmsghdr;
  struct in6_pktinfo pi6;
};

union openvpn_pktinfo {
	struct openvpn_in4_pktinfo msgpi4;
	struct openvpn_in6_pktinfo msgpi6;
};
#pragma pack()

static socklen_t
link_socket_read_udp_posix_recvmsg (struct link_socket *sock,
				    struct buffer *buf,
				    int maxsize,
				    struct link_socket_actual *from)
{
  struct iovec iov;
  union openvpn_pktinfo opi;
  struct msghdr mesg;
  socklen_t fromlen = sizeof (from->dest.addr);

  iov.iov_base = BPTR (buf);
  iov.iov_len = maxsize;
  mesg.msg_iov = &iov;
  mesg.msg_iovlen = 1;
  mesg.msg_name = &from->dest.addr;
  mesg.msg_namelen = fromlen;
  mesg.msg_control = &opi;
  mesg.msg_controllen = sizeof opi;
  buf->len = recvmsg (sock->sd, &mesg, 0);
  if (buf->len >= 0)
    {
      struct cmsghdr *cmsg;
      fromlen = mesg.msg_namelen;
      cmsg = CMSG_FIRSTHDR (&mesg);
      if (cmsg != NULL
	  && CMSG_NXTHDR (&mesg, cmsg) == NULL
#ifdef IP_PKTINFO
	  && cmsg->cmsg_level == SOL_IP 
	  && cmsg->cmsg_type == IP_PKTINFO
#elif defined(IP_RECVDSTADDR)
	  && cmsg->cmsg_level == IPPROTO_IP
	  && cmsg->cmsg_type == IP_RECVDSTADDR
#else
#error ENABLE_IP_PKTINFO is set without IP_PKTINFO xor IP_RECVDSTADDR (fix syshead.h)
#endif
	  && cmsg->cmsg_len >= sizeof (struct openvpn_in4_pktinfo))
	{
#ifdef IP_PKTINFO
	  struct in_pktinfo *pkti = (struct in_pktinfo *) CMSG_DATA (cmsg);
	  from->pi.in4.ipi_ifindex = pkti->ipi_ifindex;
	  from->pi.in4.ipi_spec_dst = pkti->ipi_spec_dst;
#elif defined(IP_RECVDSTADDR)
	  from->pi.in4 = *(struct in_addr*) CMSG_DATA (cmsg);
#else
#error ENABLE_IP_PKTINFO is set without IP_PKTINFO xor IP_RECVDSTADDR (fix syshead.h)
#endif
	}
      else if (cmsg != NULL
	  && CMSG_NXTHDR (&mesg, cmsg) == NULL
	  && cmsg->cmsg_level == IPPROTO_IPV6 
	  && cmsg->cmsg_type == IPV6_PKTINFO
	  && cmsg->cmsg_len >= sizeof (struct openvpn_in6_pktinfo))
	{
	  struct in6_pktinfo *pkti6 = (struct in6_pktinfo *) CMSG_DATA (cmsg);
	  from->pi.in6.ipi6_ifindex = pkti6->ipi6_ifindex;
	  from->pi.in6.ipi6_addr = pkti6->ipi6_addr;
	}
    }
  return fromlen;
}
#endif

int
link_socket_read_udp_posix (struct link_socket *sock,
			    struct buffer *buf,
			    int maxsize,
			    struct link_socket_actual *from)
{
  socklen_t fromlen = sizeof (from->dest.addr);
  socklen_t expectedlen = af_addr_size(proto_sa_family(sock->info.proto));
  addr_zero_host(&from->dest);
  ASSERT (buf_safe (buf, maxsize));
#if ENABLE_IP_PKTINFO
  /* Both PROTO_UDPv4 and PROTO_UDPv6 */
  if (proto_is_udp(sock->info.proto) && sock->sockflags & SF_USE_IP_PKTINFO)
    fromlen = link_socket_read_udp_posix_recvmsg (sock, buf, maxsize, from);
  else
#endif
    buf->len = recvfrom (sock->sd, BPTR (buf), maxsize, 0,
			 &from->dest.addr.sa, &fromlen);
  if (buf->len >= 0 && expectedlen && fromlen != expectedlen)
    bad_address_length (fromlen, expectedlen);
  return buf->len;
}

#endif

/*
 * Socket Write Routines
 */

int
link_socket_write_tcp (struct link_socket *sock,
		       struct buffer *buf,
		       struct link_socket_actual *to)
{
  packet_size_type len = BLEN (buf);
  dmsg (D_STREAM_DEBUG, "STREAM: WRITE %d offset=%d", (int)len, buf->offset);
  ASSERT (len <= sock->stream_buf.maxlen);
  len = htonps (len);
  ASSERT (buf_write_prepend (buf, &len, sizeof (len)));
#ifdef WIN32
  return link_socket_write_win32 (sock, buf, to);
#else
  return link_socket_write_tcp_posix (sock, buf, to);  
#endif
}

#if ENABLE_IP_PKTINFO

int
link_socket_write_udp_posix_sendmsg (struct link_socket *sock,
				     struct buffer *buf,
				     struct link_socket_actual *to)
{
  struct iovec iov;
  struct msghdr mesg;
  struct cmsghdr *cmsg;

  iov.iov_base = BPTR (buf);
  iov.iov_len = BLEN (buf);
  mesg.msg_iov = &iov;
  mesg.msg_iovlen = 1;
  switch (sock->info.lsa->remote.addr.sa.sa_family)
    {
    case AF_INET:
      {
        struct openvpn_in4_pktinfo msgpi4;
        mesg.msg_name = &to->dest.addr.sa;
        mesg.msg_namelen = sizeof (struct sockaddr_in);
        mesg.msg_control = &msgpi4;
        mesg.msg_controllen = sizeof msgpi4;
        mesg.msg_flags = 0;
        cmsg = CMSG_FIRSTHDR (&mesg);
        cmsg->cmsg_len = sizeof (struct openvpn_in4_pktinfo);
#ifdef HAVE_IN_PKTINFO
        cmsg->cmsg_level = SOL_IP;
        cmsg->cmsg_type = IP_PKTINFO;
	{
        struct in_pktinfo *pkti;
        pkti = (struct in_pktinfo *) CMSG_DATA (cmsg);
        pkti->ipi_ifindex = to->pi.in4.ipi_ifindex;
        pkti->ipi_spec_dst = to->pi.in4.ipi_spec_dst;
        pkti->ipi_addr.s_addr = 0;
	}
#elif defined(IP_RECVDSTADDR)
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_RECVDSTADDR;
        *(struct in_addr *) CMSG_DATA (cmsg) = to->pi.in4;
#else
#error ENABLE_IP_PKTINFO is set without IP_PKTINFO xor IP_RECVDSTADDR (fix syshead.h)
#endif
        break;
      }
    case AF_INET6:
      {
        struct openvpn_in6_pktinfo msgpi6;
        struct in6_pktinfo *pkti6;
        mesg.msg_name = &to->dest.addr.sa;
        mesg.msg_namelen = sizeof (struct sockaddr_in6);
        mesg.msg_control = &msgpi6;
        mesg.msg_controllen = sizeof msgpi6;
        mesg.msg_flags = 0;
        cmsg = CMSG_FIRSTHDR (&mesg);
        cmsg->cmsg_len = sizeof (struct openvpn_in6_pktinfo);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        pkti6 = (struct in6_pktinfo *) CMSG_DATA (cmsg);
        pkti6->ipi6_ifindex = to->pi.in6.ipi6_ifindex;
        pkti6->ipi6_addr = to->pi.in6.ipi6_addr;
        break;
      }
    default: ASSERT(0);
    }
  return sendmsg (sock->sd, &mesg, 0);
}

#endif

/*
 * Win32 overlapped socket I/O functions.
 */

#ifdef WIN32

int
socket_recv_queue (struct link_socket *sock, int maxsize)
{
  if (sock->reads.iostate == IOSTATE_INITIAL)
    {
      WSABUF wsabuf[1];
      int status;

      /* reset buf to its initial state */
      if (proto_is_udp(sock->info.proto))
	{
	  sock->reads.buf = sock->reads.buf_init;
	}
      else if (proto_is_tcp(sock->info.proto))
	{
	  stream_buf_get_next (&sock->stream_buf, &sock->reads.buf);
	}
      else
	{
	  ASSERT (0);
	}

      /* Win32 docs say it's okay to allocate the wsabuf on the stack */
      wsabuf[0].buf = BPTR (&sock->reads.buf);
      wsabuf[0].len = maxsize ? maxsize : BLEN (&sock->reads.buf);

      /* check for buffer overflow */
      ASSERT (wsabuf[0].len <= BLEN (&sock->reads.buf));

      /* the overlapped read will signal this event on I/O completion */
      ASSERT (ResetEvent (sock->reads.overlapped.hEvent));
      sock->reads.flags = 0;

      if (proto_is_udp(sock->info.proto))
	{
	  sock->reads.addr_defined = true;
	  if (sock->info.proto == PROTO_UDPv6)
	    sock->reads.addrlen = sizeof (sock->reads.addr6);
	  else
	    sock->reads.addrlen = sizeof (sock->reads.addr);
	  status = WSARecvFrom(
			       sock->sd,
			       wsabuf,
			       1,
			       &sock->reads.size,
			       &sock->reads.flags,
			       (struct sockaddr *) &sock->reads.addr,
			       &sock->reads.addrlen,
			       &sock->reads.overlapped,
			       NULL);
	}
      else if (proto_is_tcp(sock->info.proto))
	{
	  sock->reads.addr_defined = false;
	  status = WSARecv(
			   sock->sd,
			   wsabuf,
			   1,
			   &sock->reads.size,
			   &sock->reads.flags,
			   &sock->reads.overlapped,
			   NULL);
	}
      else
	{
	  status = 0;
	  ASSERT (0);
	}

      if (!status) /* operation completed immediately? */
	{
	  int addrlen = af_addr_size(sock->info.lsa->local.addr.sa.sa_family);
	  if (sock->reads.addr_defined && sock->reads.addrlen != addrlen)
	    bad_address_length (sock->reads.addrlen, addrlen);
	  sock->reads.iostate = IOSTATE_IMMEDIATE_RETURN;

	  /* since we got an immediate return, we must signal the event object ourselves */
	  ASSERT (SetEvent (sock->reads.overlapped.hEvent));
	  sock->reads.status = 0;

	  dmsg (D_WIN32_IO, "WIN32 I/O: Socket Receive immediate return [%d,%d]",
	       (int) wsabuf[0].len,
	       (int) sock->reads.size);	       
	}
      else
	{
	  status = WSAGetLastError (); 
	  if (status == WSA_IO_PENDING) /* operation queued? */
	    {
	      sock->reads.iostate = IOSTATE_QUEUED;
	      sock->reads.status = status;
	      dmsg (D_WIN32_IO, "WIN32 I/O: Socket Receive queued [%d]",
		   (int) wsabuf[0].len);
	    }
	  else /* error occurred */
	    {
	      struct gc_arena gc = gc_new ();
	      ASSERT (SetEvent (sock->reads.overlapped.hEvent));
	      sock->reads.iostate = IOSTATE_IMMEDIATE_RETURN;
	      sock->reads.status = status;
	      dmsg (D_WIN32_IO, "WIN32 I/O: Socket Receive error [%d]: %s",
		   (int) wsabuf[0].len,
		   strerror_win32 (status, &gc));
	      gc_free (&gc);
	    }
	}
    }
  return sock->reads.iostate;
}

int
socket_send_queue (struct link_socket *sock, struct buffer *buf, const struct link_socket_actual *to)
{
  if (sock->writes.iostate == IOSTATE_INITIAL)
    {
      WSABUF wsabuf[1];
      int status;
 
      /* make a private copy of buf */
      sock->writes.buf = sock->writes.buf_init;
      sock->writes.buf.len = 0;
      ASSERT (buf_copy (&sock->writes.buf, buf));

      /* Win32 docs say it's okay to allocate the wsabuf on the stack */
      wsabuf[0].buf = BPTR (&sock->writes.buf);
      wsabuf[0].len = BLEN (&sock->writes.buf);

      /* the overlapped write will signal this event on I/O completion */
      ASSERT (ResetEvent (sock->writes.overlapped.hEvent));
      sock->writes.flags = 0;

      if (proto_is_udp(sock->info.proto))
	{
	  /* set destination address for UDP writes */
	  sock->writes.addr_defined = true;
	  if (sock->info.proto == PROTO_UDPv6)
	    {
	      sock->writes.addr6 = to->dest.addr.in6;
	      sock->writes.addrlen = sizeof (sock->writes.addr6);
	    }
	  else
	    {
	      sock->writes.addr = to->dest.addr.in4;
	      sock->writes.addrlen = sizeof (sock->writes.addr);
	    }

	  status = WSASendTo(
			       sock->sd,
			       wsabuf,
			       1,
			       &sock->writes.size,
			       sock->writes.flags,
			       (struct sockaddr *) &sock->writes.addr,
			       sock->writes.addrlen,
			       &sock->writes.overlapped,
			       NULL);
	}
      else if (proto_is_tcp(sock->info.proto))
	{
	  /* destination address for TCP writes was established on connection initiation */
	  sock->writes.addr_defined = false;

	  status = WSASend(
			   sock->sd,
			   wsabuf,
			   1,
			   &sock->writes.size,
			   sock->writes.flags,
			   &sock->writes.overlapped,
			   NULL);
	}
      else 
	{
	  status = 0;
	  ASSERT (0);
	}

      if (!status) /* operation completed immediately? */
	{
	  sock->writes.iostate = IOSTATE_IMMEDIATE_RETURN;

	  /* since we got an immediate return, we must signal the event object ourselves */
	  ASSERT (SetEvent (sock->writes.overlapped.hEvent));

	  sock->writes.status = 0;

	  dmsg (D_WIN32_IO, "WIN32 I/O: Socket Send immediate return [%d,%d]",
	       (int) wsabuf[0].len,
	       (int) sock->writes.size);	       
	}
      else
	{
	  status = WSAGetLastError (); 
	  if (status == WSA_IO_PENDING) /* operation queued? */
	    {
	      sock->writes.iostate = IOSTATE_QUEUED;
	      sock->writes.status = status;
	      dmsg (D_WIN32_IO, "WIN32 I/O: Socket Send queued [%d]",
		   (int) wsabuf[0].len);
	    }
	  else /* error occurred */
	    {
	      struct gc_arena gc = gc_new ();
	      ASSERT (SetEvent (sock->writes.overlapped.hEvent));
	      sock->writes.iostate = IOSTATE_IMMEDIATE_RETURN;
	      sock->writes.status = status;

	      dmsg (D_WIN32_IO, "WIN32 I/O: Socket Send error [%d]: %s",
		   (int) wsabuf[0].len,
		   strerror_win32 (status, &gc));

	      gc_free (&gc);
	    }
	}
    }
  return sock->writes.iostate;
}

int
socket_finalize (SOCKET s,
		 struct overlapped_io *io,
		 struct buffer *buf,
		 struct link_socket_actual *from)
{
  int ret = -1;
  BOOL status;

  switch (io->iostate)
    {
    case IOSTATE_QUEUED:
      status = WSAGetOverlappedResult(
				      s,
				      &io->overlapped,
				      &io->size,
				      FALSE,
				      &io->flags
				      );
      if (status)
	{
	  /* successful return for a queued operation */
	  if (buf)
	    *buf = io->buf;
	  ret = io->size;
	  io->iostate = IOSTATE_INITIAL;
	  ASSERT (ResetEvent (io->overlapped.hEvent));

	  dmsg (D_WIN32_IO, "WIN32 I/O: Socket Completion success [%d]", ret);
	}
      else
	{
	  /* error during a queued operation */
	  ret = -1;
	  if (WSAGetLastError() != WSA_IO_INCOMPLETE)
	    {
	      /* if no error (i.e. just not finished yet), then DON'T execute this code */
	      io->iostate = IOSTATE_INITIAL;
	      ASSERT (ResetEvent (io->overlapped.hEvent));
	      msg (D_WIN32_IO | M_ERRNO, "WIN32 I/O: Socket Completion error");
	    }
	}
      break;

    case IOSTATE_IMMEDIATE_RETURN:
      io->iostate = IOSTATE_INITIAL;
      ASSERT (ResetEvent (io->overlapped.hEvent));
      if (io->status)
	{
	  /* error return for a non-queued operation */
	  WSASetLastError (io->status);
	  ret = -1;
	  msg (D_WIN32_IO | M_ERRNO, "WIN32 I/O: Socket Completion non-queued error");
	}
      else
	{
	  /* successful return for a non-queued operation */
	  if (buf)
	    *buf = io->buf;
	  ret = io->size;
	  dmsg (D_WIN32_IO, "WIN32 I/O: Socket Completion non-queued success [%d]", ret);
	}
      break;

    case IOSTATE_INITIAL: /* were we called without proper queueing? */
      WSASetLastError (WSAEINVAL);
      ret = -1;
      dmsg (D_WIN32_IO, "WIN32 I/O: Socket Completion BAD STATE");
      break;

    default:
      ASSERT (0);
    }
  
  /* return from address if requested */
  if (from)
    {
      if (ret >= 0 && io->addr_defined)
	{
	  /* TODO(jjo): streamline this mess */
	  /* in this func we dont have relevant info about the PF_ of this
	   * endpoint, as link_socket_actual will be zero for the 1st received packet
	   *
	   * Test for inets PF_ possible sizes
	   */
	  switch (io->addrlen)
	    {
	    case sizeof(struct sockaddr_in):
	    case sizeof(struct sockaddr_in6):
	    /* TODO(jjo): for some reason (?) I'm getting 24,28 for AF_INET6
	     * under WIN32*/
	    case sizeof(struct sockaddr_in6)-4:
	      break;
	    default:
	      bad_address_length (io->addrlen, af_addr_size(io->addr.sin_family));
	    }

	  switch (io->addr.sin_family)
	    {
	    case AF_INET:
	      from->dest.addr.in4 = io->addr;
	      break;
	    case AF_INET6:
	      from->dest.addr.in6 = io->addr6;
	      break;
	    }
	}
      else
	CLEAR (from->dest.addr);
    }
  
  if (buf)
    buf->len = ret;
  return ret;
}

#endif /* WIN32 */

/*
 * Socket event notification
 */

unsigned int
socket_set (struct link_socket *s,
	    struct event_set *es,
	    unsigned int rwflags,
	    void *arg,
	    unsigned int *persistent)
{
  if (s)
    {
      if ((rwflags & EVENT_READ) && !stream_buf_read_setup (s))
	{
	  ASSERT (!persistent);
	  rwflags &= ~EVENT_READ;
	}
      
#ifdef WIN32
      if (rwflags & EVENT_READ)
	socket_recv_queue (s, 0);
#endif

      /* if persistent is defined, call event_ctl only if rwflags has changed since last call */
      if (!persistent || *persistent != rwflags)
	{
	  event_ctl (es, socket_event_handle (s), rwflags, arg);
	  if (persistent)
	    *persistent = rwflags;
	}

      s->rwflags_debug = rwflags;
    }
  return rwflags;
}

void
sd_close (socket_descriptor_t *sd)
{
  if (sd && socket_defined (*sd))
    {
      openvpn_close_socket (*sd);
      *sd = SOCKET_UNDEFINED;
    }
}

#if UNIX_SOCK_SUPPORT

/*
 * code for unix domain sockets
 */

const char *
sockaddr_unix_name (const struct sockaddr_un *local, const char *null)
{
  if (local && local->sun_family == PF_UNIX)
    return local->sun_path;
  else
    return null;
}

socket_descriptor_t
create_socket_unix (void)
{
  socket_descriptor_t sd;

  if ((sd = socket (PF_UNIX, SOCK_STREAM, 0)) < 0)
    msg (M_ERR, "Cannot create unix domain socket");
  return sd;
}

void
socket_bind_unix (socket_descriptor_t sd,
		  struct sockaddr_un *local,
		  const char *prefix)
{
  struct gc_arena gc = gc_new ();

#ifdef HAVE_UMASK
  const mode_t orig_umask = umask (0);
#endif

  if (bind (sd, (struct sockaddr *) local, sizeof (struct sockaddr_un)))
    {
      const int errnum = openvpn_errno ();
      msg (M_FATAL, "%s: Socket bind[%d] failed on unix domain socket %s: %s",
	   prefix,
	   (int)sd,
           sockaddr_unix_name (local, "NULL"),
           strerror_ts (errnum, &gc));
    }

#ifdef HAVE_UMASK
  umask (orig_umask);
#endif

  gc_free (&gc);
}

socket_descriptor_t
socket_accept_unix (socket_descriptor_t sd,
		    struct sockaddr_un *remote)
{
  socklen_t remote_len = sizeof (struct sockaddr_un);
  socket_descriptor_t ret;

  CLEAR (*remote);
  ret = accept (sd, (struct sockaddr *) remote, &remote_len);
  return ret;
}

int
socket_connect_unix (socket_descriptor_t sd,
		     struct sockaddr_un *remote)
{
  int status = connect (sd, (struct sockaddr *) remote, sizeof (struct sockaddr_un));
  if (status)
    status = openvpn_errno ();
  return status;
}

void
sockaddr_unix_init (struct sockaddr_un *local, const char *path)
{
  local->sun_family = PF_UNIX;
  strncpynt (local->sun_path, path, sizeof (local->sun_path));
}

void
socket_delete_unix (const struct sockaddr_un *local)
{
  const char *name = sockaddr_unix_name (local, NULL);
#ifdef HAVE_UNLINK
  if (name && strlen (name))
    unlink (name);
#endif
}

bool
unix_socket_get_peer_uid_gid (const socket_descriptor_t sd, int *uid, int *gid)
{
#ifdef HAVE_GETPEEREID
  uid_t u;
  gid_t g;
  if (getpeereid (sd, &u, &g) == -1) 
    return false;
  if (uid)
    *uid = u;
  if (gid)
    *gid = g;
  return true;
#elif defined(SO_PEERCRED)
  struct ucred peercred;
  socklen_t so_len = sizeof(peercred);
  if (getsockopt(sd, SOL_SOCKET, SO_PEERCRED, &peercred, &so_len) == -1) 
    return false;
  if (uid)
    *uid = peercred.uid;
  if (gid)
    *gid = peercred.gid;
  return true;
#else
  return false;
#endif
}

#endif
