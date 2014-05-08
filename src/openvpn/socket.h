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

#ifndef SOCKET_H
#define SOCKET_H

#include "buffer.h"
#include "common.h"
#include "error.h"
#include "proto.h"
#include "mtu.h"
#include "win32.h"
#include "event.h"
#include "proxy.h"
#include "socks.h"
#include "misc.h"

/*
 * OpenVPN's default port number as assigned by IANA.
 */
#define OPENVPN_PORT 1194

/*
 * Maximum size passed passed to setsockopt SNDBUF/RCVBUF
 */
#define SOCKET_SND_RCV_BUF_MAX 1000000

/*
 * Number of seconds that "resolv-retry infinite"
 * represents.
 */
#define RESOLV_RETRY_INFINITE 1000000000

/* 
 * packet_size_type is used to communicate packet size
 * over the wire when stream oriented protocols are
 * being used
 */

typedef uint16_t packet_size_type;

/* convert a packet_size_type from host to network order */
#define htonps(x) htons(x)

/* convert a packet_size_type from network to host order */
#define ntohps(x) ntohs(x)

/* OpenVPN sockaddr struct */
struct openvpn_sockaddr
{
  /*int dummy;*/ /* add offset to force a bug if sa not explicitly dereferenced */
  union {
    struct sockaddr sa;
    struct sockaddr_in in4;
    struct sockaddr_in6 in6;
  } addr;
};

/* actual address of remote, based on source address of received packets */
struct link_socket_actual
{
  /*int dummy;*/ /* add offset to force a bug if dest not explicitly dereferenced */
  struct openvpn_sockaddr dest;
#if ENABLE_IP_PKTINFO
  union {
#ifdef HAVE_IN_PKTINFO
    struct in_pktinfo in4;
#elif defined(IP_RECVDSTADDR)
    struct in_addr in4;
#endif
    struct in6_pktinfo in6;
  } pi;
#endif
};

/* IP addresses which are persistant across SIGUSR1s */
struct link_socket_addr
{
  struct openvpn_sockaddr local;
  struct openvpn_sockaddr remote;   /* initial remote */
  struct link_socket_actual actual; /* reply to this address */
};

struct link_socket_info
{
  struct link_socket_addr *lsa;
  bool connection_established;
  const char *ipchange_command;
  const struct plugin_list *plugins;
  bool remote_float;  
  int proto;                    /* Protocol (PROTO_x defined below) */
  int mtu_changed;              /* Set to true when mtu value is changed */
};

/*
 * Used to extract packets encapsulated in streams into a buffer,
 * in this case IP packets embedded in a TCP stream.
 */
struct stream_buf
{
  struct buffer buf_init;
  struct buffer residual;
  int maxlen;
  bool residual_fully_formed;

  struct buffer buf;
  struct buffer next;
  int len;     /* -1 if not yet known */

  bool error;  /* if true, fatal TCP error has occurred,
		  requiring that connection be restarted */
#if PORT_SHARE
# define PS_DISABLED 0
# define PS_ENABLED  1
# define PS_FOREIGN  2
  int port_share_state;
#endif
};

/*
 * Used to set socket buffer sizes
 */
struct socket_buffer_size
{
  int rcvbuf;
  int sndbuf;
};

/*
 * This is the main socket structure used by OpenVPN.  The SOCKET_
 * defines try to abstract away our implementation differences between
 * using sockets on Posix vs. Win32.
 */
struct link_socket
{
  struct link_socket_info info;

  socket_descriptor_t sd;

#ifdef ENABLE_SOCKS
  socket_descriptor_t ctrl_sd;  /* only used for UDP over Socks */
#endif

#ifdef WIN32
  struct overlapped_io reads;
  struct overlapped_io writes;
  struct rw_handle rw_handle;
  struct rw_handle listen_handle; /* For listening on TCP socket in server mode */
#endif

  /* used for printing status info only */
  unsigned int rwflags_debug;

  /* used for long-term queueing of pre-accepted socket listen */
  bool listen_persistent_queued;

  /* Does config file contain any <connection> ... </connection> blocks? */
  bool connection_profiles_defined;

  const char *remote_host;
  int remote_port;
  const char *local_host;
  int local_port;
  bool bind_local;

# define INETD_NONE   0
# define INETD_WAIT   1
# define INETD_NOWAIT 2
  int inetd;

# define LS_MODE_DEFAULT           0
# define LS_MODE_TCP_LISTEN        1
# define LS_MODE_TCP_ACCEPT_FROM   2
  int mode;

  int resolve_retry_seconds;
  int connect_retry_seconds;
  int connect_timeout;
  int connect_retry_max;
  int mtu_discover_type;

  struct socket_buffer_size socket_buffer_sizes;

  int mtu;                      /* OS discovered MTU, or 0 if unknown */

  bool did_resolve_remote;

# define SF_USE_IP_PKTINFO (1<<0)
# define SF_TCP_NODELAY (1<<1)
# define SF_PORT_SHARE (1<<2)
# define SF_HOST_RANDOMIZE (1<<3)
# define SF_GETADDRINFO_DGRAM (1<<4)
  unsigned int sockflags;

  /* for stream sockets */
  struct stream_buf stream_buf;
  struct buffer stream_buf_data;
  bool stream_reset;

#ifdef ENABLE_HTTP_PROXY
  /* HTTP proxy */
  struct http_proxy_info *http_proxy;
#endif

#ifdef ENABLE_SOCKS
  /* Socks proxy */
  struct socks_proxy_info *socks_proxy;
  struct link_socket_actual socks_relay; /* Socks UDP relay address */
#endif

#if defined(ENABLE_HTTP_PROXY) || defined(ENABLE_SOCKS)
  /* The OpenVPN server we will use the proxy to connect to */
  const char *proxy_dest_host;
  int proxy_dest_port;
#endif

#if PASSTOS_CAPABILITY
  /* used to get/set TOS. */
#if defined(TARGET_LINUX)
  uint8_t ptos;
#else /* all the BSDs, Solaris, MacOS use plain "int" -> see "man ip" there */
  int  ptos;
#endif
  bool ptos_defined;
#endif

#ifdef ENABLE_DEBUG
  int gremlin; /* --gremlin bits */
#endif
};

/*
 * Some Posix/Win32 differences.
 */

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifdef WIN32

#define openvpn_close_socket(s) closesocket(s)

int socket_recv_queue (struct link_socket *sock, int maxsize);

int socket_send_queue (struct link_socket *sock,
		       struct buffer *buf,
		       const struct link_socket_actual *to);

int socket_finalize (
		     SOCKET s,
		     struct overlapped_io *io,
		     struct buffer *buf,
		     struct link_socket_actual *from);

#else

#define openvpn_close_socket(s) close(s)

#endif

struct link_socket *link_socket_new (void);

void socket_bind (socket_descriptor_t sd,
		  struct openvpn_sockaddr *local,
		  const char *prefix);

int openvpn_connect (socket_descriptor_t sd,
		     struct openvpn_sockaddr *remote,
		     int connect_timeout,
		     volatile int *signal_received);

/*
 * Initialize link_socket object.
 */

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
			 unsigned int sockflags);

void link_socket_init_phase2 (struct link_socket *sock,
			      const struct frame *frame,
			      volatile int *signal_received);

void socket_adjust_frame_parameters (struct frame *frame, int proto);

void frame_adjust_path_mtu (struct frame *frame, int pmtu, int proto);

void link_socket_close (struct link_socket *sock);

void sd_close (socket_descriptor_t *sd);

#define PS_SHOW_PORT_IF_DEFINED (1<<0)
#define PS_SHOW_PORT            (1<<1)
#define PS_SHOW_PKTINFO         (1<<2)
#define PS_DONT_SHOW_ADDR       (1<<3)

const char *print_sockaddr_ex (const struct openvpn_sockaddr *addr,
			       const char* separator,
			       const unsigned int flags,
			       struct gc_arena *gc);


const char *print_sockaddr (const struct openvpn_sockaddr *addr,
			    struct gc_arena *gc);

const char *print_link_socket_actual_ex (const struct link_socket_actual *act,
					 const char* separator,
					 const unsigned int flags,
					 struct gc_arena *gc);

const char *print_link_socket_actual (const struct link_socket_actual *act,
				      struct gc_arena *gc);


#define IA_EMPTY_IF_UNDEF (1<<0)
#define IA_NET_ORDER      (1<<1)
const char *print_in_addr_t (in_addr_t addr, unsigned int flags, struct gc_arena *gc);
const char *print_in6_addr  (struct in6_addr addr6, unsigned int flags, struct gc_arena *gc);
struct in6_addr add_in6_addr( struct in6_addr base, uint32_t add );

#define SA_IP_PORT        (1<<0)
#define SA_SET_IF_NONZERO (1<<1)
void setenv_sockaddr (struct env_set *es,
		      const char *name_prefix,
		      const struct openvpn_sockaddr *addr,
		      const unsigned int flags);

void setenv_in_addr_t (struct env_set *es,
		       const char *name_prefix,
		       in_addr_t addr,
		       const unsigned int flags);

void setenv_link_socket_actual (struct env_set *es,
				const char *name_prefix,
				const struct link_socket_actual *act,
				const unsigned int flags);

void bad_address_length (int actual, int expected);

/* IPV4_INVALID_ADDR: returned by link_socket_current_remote()
 * to ease redirect-gateway logic for ipv4 tunnels on ipv6 endpoints
 */
#define IPV4_INVALID_ADDR 0xffffffff
in_addr_t link_socket_current_remote (const struct link_socket_info *info);

void link_socket_connection_initiated (const struct buffer *buf,
				       struct link_socket_info *info,
				       const struct link_socket_actual *addr,
				       const char *common_name,
				       struct env_set *es);

void link_socket_bad_incoming_addr (struct buffer *buf,
				    const struct link_socket_info *info,
				    const struct link_socket_actual *from_addr);

void link_socket_bad_outgoing_addr (void);

void setenv_trusted (struct env_set *es, const struct link_socket_info *info);

bool link_socket_update_flags (struct link_socket *ls, unsigned int sockflags);
void link_socket_update_buffer_sizes (struct link_socket *ls, int rcvbuf, int sndbuf);

/*
 * Low-level functions
 */

/* return values of openvpn_inet_aton */
#define OIA_HOSTNAME   0
#define OIA_IP         1
#define OIA_ERROR     -1
int openvpn_inet_aton (const char *dotted_quad, struct in_addr *addr);

/* integrity validation on pulled options */
bool ip_addr_dotted_quad_safe (const char *dotted_quad);
bool ip_or_dns_addr_safe (const char *addr, const bool allow_fqdn);
bool mac_addr_safe (const char *mac_addr);
bool ipv6_addr_safe (const char *ipv6_text_addr);

socket_descriptor_t create_socket_tcp (int af);

socket_descriptor_t socket_do_accept (socket_descriptor_t sd,
				      struct link_socket_actual *act,
				      const bool nowait);
/*
 * proto related
 */
bool proto_is_net(int proto);
bool proto_is_dgram(int proto);
bool proto_is_udp(int proto);
bool proto_is_tcp(int proto);


#if UNIX_SOCK_SUPPORT

socket_descriptor_t create_socket_unix (void);

void socket_bind_unix (socket_descriptor_t sd,
		       struct sockaddr_un *local,
		       const char *prefix);

socket_descriptor_t socket_accept_unix (socket_descriptor_t sd,
					struct sockaddr_un *remote);

int socket_connect_unix (socket_descriptor_t sd,
			 struct sockaddr_un *remote);

void sockaddr_unix_init (struct sockaddr_un *local, const char *path);

const char *sockaddr_unix_name (const struct sockaddr_un *local, const char *null);

void socket_delete_unix (const struct sockaddr_un *local);

bool unix_socket_get_peer_uid_gid (const socket_descriptor_t sd, int *uid, int *gid);

#endif

/*
 * DNS resolution
 */

#define GETADDR_RESOLVE               (1<<0)
#define GETADDR_FATAL                 (1<<1)
#define GETADDR_HOST_ORDER            (1<<2)
#define GETADDR_MENTION_RESOLVE_RETRY (1<<3)
#define GETADDR_FATAL_ON_SIGNAL       (1<<4)
#define GETADDR_WARN_ON_SIGNAL        (1<<5)
#define GETADDR_MSG_VIRT_OUT          (1<<6)
#define GETADDR_TRY_ONCE              (1<<7)
#define GETADDR_UPDATE_MANAGEMENT_STATE (1<<8)
#define GETADDR_RANDOMIZE             (1<<9)

in_addr_t getaddr (unsigned int flags,
		   const char *hostname,
		   int resolve_retry_seconds,
		   bool *succeeded,
		   volatile int *signal_received);

int openvpn_getaddrinfo (unsigned int flags,
                         const char *hostname,
                         int resolve_retry_seconds,
                         volatile int *signal_received,
                         int ai_family,
                         struct addrinfo **res);

/*
 * Transport protocol naming and other details.
 */

/* 
 * Use enum's instead of #define to allow for easier
 * optional proto support
 */
enum proto_num {
	PROTO_NONE, /* catch for uninitialized */
	PROTO_UDPv4,
	PROTO_TCPv4_SERVER,
	PROTO_TCPv4_CLIENT,
	PROTO_TCPv4,
	PROTO_UDPv6,
	PROTO_TCPv6_SERVER,
	PROTO_TCPv6_CLIENT,
	PROTO_TCPv6,
	PROTO_N
};

int ascii2proto (const char* proto_name);
const char *proto2ascii (int proto, bool display_form);
const char *proto2ascii_all (struct gc_arena *gc);
int proto_remote (int proto, bool remote);
const char *addr_family_name(int af);

/*
 * Overhead added to packets by various protocols.
 */
#define IPv4_UDP_HEADER_SIZE              28
#define IPv4_TCP_HEADER_SIZE              40
#define IPv6_UDP_HEADER_SIZE              48
#define IPv6_TCP_HEADER_SIZE              60

extern const int proto_overhead[];

static inline int
datagram_overhead (int proto)
{
  ASSERT (proto >= 0 && proto < PROTO_N);
  return proto_overhead [proto];
}

/*
 * Misc inline functions
 */

static inline bool
legal_ipv4_port (int port)
{
  return port > 0 && port < 65536;
}

static inline bool
link_socket_proto_connection_oriented (int proto)
{
  return !proto_is_dgram(proto);
}

static inline bool
link_socket_connection_oriented (const struct link_socket *sock)
{
  if (sock)
    return link_socket_proto_connection_oriented (sock->info.proto);
  else
    return false;
}

static inline bool
addr_defined (const struct openvpn_sockaddr *addr)
{
  if (!addr) return 0;
  switch (addr->addr.sa.sa_family) {
    case AF_INET: return addr->addr.in4.sin_addr.s_addr != 0;
    case AF_INET6: return !IN6_IS_ADDR_UNSPECIFIED(&addr->addr.in6.sin6_addr);
    default: return 0;
  }
}
static inline bool
addr_defined_ipi (const struct link_socket_actual *lsa)
{
#if ENABLE_IP_PKTINFO
  if (!lsa) return 0;
  switch (lsa->dest.addr.sa.sa_family) {
#ifdef HAVE_IN_PKTINFO
    case AF_INET: return lsa->pi.in4.ipi_spec_dst.s_addr != 0;
#elif defined(IP_RECVDSTADDR)
    case AF_INET: return lsa->pi.in4.s_addr != 0;
#endif
    case AF_INET6: return !IN6_IS_ADDR_UNSPECIFIED(&lsa->pi.in6.ipi6_addr);
    default: return 0;
  }
#else
  ASSERT(0);
#endif
  return false;
}

static inline bool
link_socket_actual_defined (const struct link_socket_actual *act)
{
  return act && addr_defined (&act->dest);
}

static inline bool
addr_match (const struct openvpn_sockaddr *a1, const struct openvpn_sockaddr *a2)
{
  switch(a1->addr.sa.sa_family) {
    case AF_INET:
      return a1->addr.in4.sin_addr.s_addr == a2->addr.in4.sin_addr.s_addr;
    case AF_INET6:
      return IN6_ARE_ADDR_EQUAL(&a1->addr.in6.sin6_addr, &a2->addr.in6.sin6_addr);
  }
  ASSERT(0);
  return false;
}

static inline in_addr_t
addr_host (const struct openvpn_sockaddr *addr)
{
  /* 
   * "public" addr returned is checked against ifconfig for
   * possible clash: non sense for now given
   * that we do ifconfig only IPv4
   */
  if(addr->addr.sa.sa_family != AF_INET)
    return 0;
  return ntohl (addr->addr.in4.sin_addr.s_addr);
}

static inline bool
addr_port_match (const struct openvpn_sockaddr *a1, const struct openvpn_sockaddr *a2)
{
  switch(a1->addr.sa.sa_family) {
    case AF_INET:
      return a1->addr.in4.sin_addr.s_addr == a2->addr.in4.sin_addr.s_addr
	&& a1->addr.in4.sin_port == a2->addr.in4.sin_port;
    case AF_INET6:
      return IN6_ARE_ADDR_EQUAL(&a1->addr.in6.sin6_addr, &a2->addr.in6.sin6_addr) 
	&& a1->addr.in6.sin6_port == a2->addr.in6.sin6_port;
  }
  ASSERT(0);
  return false;
}

static inline bool
addr_match_proto (const struct openvpn_sockaddr *a1,
		  const struct openvpn_sockaddr *a2,
		  const int proto)
{
  return link_socket_proto_connection_oriented (proto)
    ? addr_match (a1, a2)
    : addr_port_match (a1, a2);
}

static inline void
addr_zero_host(struct openvpn_sockaddr *addr)
{
   switch(addr->addr.sa.sa_family) {
     case AF_INET:
       addr->addr.in4.sin_addr.s_addr = 0;
       break;
     case AF_INET6: 
       memset(&addr->addr.in6.sin6_addr, 0, sizeof (struct in6_addr));
       break;
   }
}

static inline void
addr_copy_sa(struct openvpn_sockaddr *dst, const struct openvpn_sockaddr *src)
{
  dst->addr = src->addr;
}

static inline void
addr_copy_host(struct openvpn_sockaddr *dst, const struct openvpn_sockaddr *src)
{
   switch(src->addr.sa.sa_family) {
     case AF_INET:
       dst->addr.in4.sin_addr.s_addr = src->addr.in4.sin_addr.s_addr;
       break;
     case AF_INET6: 
       dst->addr.in6.sin6_addr = src->addr.in6.sin6_addr;
       break;
   }
}

static inline bool
addr_inet4or6(struct sockaddr *addr)
{
	return addr->sa_family == AF_INET || addr->sa_family == AF_INET6;
}

int addr_guess_family(int proto, const char *name);
static inline int
af_addr_size(unsigned short af)
{
   switch(af) {
     case AF_INET: return sizeof (struct sockaddr_in);
     case AF_INET6: return sizeof (struct sockaddr_in6);
     default: 
#if 0
      /* could be called from socket_do_accept() with empty addr */
      msg (M_ERR, "Bad address family: %d\n", af);
      ASSERT(0);
#endif
     	return 0;
   }
}

static inline bool
link_socket_actual_match (const struct link_socket_actual *a1, const struct link_socket_actual *a2)
{
  return addr_port_match (&a1->dest, &a2->dest);
}

#if PORT_SHARE

static inline bool
socket_foreign_protocol_detected (const struct link_socket *sock)
{
  return link_socket_connection_oriented (sock)
    && sock->stream_buf.port_share_state == PS_FOREIGN;
}

static inline const struct buffer *
socket_foreign_protocol_head (const struct link_socket *sock)
{
  return &sock->stream_buf.buf;
}

static inline int
socket_foreign_protocol_sd (const struct link_socket *sock)
{
  return sock->sd;
}

#endif

static inline bool
socket_connection_reset (const struct link_socket *sock, int status)
{
  if (link_socket_connection_oriented (sock))
    {
      if (sock->stream_reset || sock->stream_buf.error)
	return true;
      else if (status < 0)
	{
	  const int err = openvpn_errno ();
#ifdef WIN32
	  return err == WSAECONNRESET || err == WSAECONNABORTED;
#else
	  return err == ECONNRESET;
#endif
	}
    }
  return false;
}

static inline bool
link_socket_verify_incoming_addr (struct buffer *buf,
				  const struct link_socket_info *info,
				  const struct link_socket_actual *from_addr)
{
  if (buf->len > 0)
    {
      switch (from_addr->dest.addr.sa.sa_family) {
	case AF_INET6:
	case AF_INET:
	  if (!link_socket_actual_defined (from_addr))
	    return false;
	  if (info->remote_float || !addr_defined (&info->lsa->remote))
	    return true;
	  if (addr_match_proto (&from_addr->dest, &info->lsa->remote, info->proto))
	    return true;
      }
    }
  return false;
}

static inline void
link_socket_get_outgoing_addr (struct buffer *buf,
			      const struct link_socket_info *info,
			      struct link_socket_actual **act)
{
  if (buf->len > 0)
    {
      struct link_socket_addr *lsa = info->lsa;
      if (link_socket_actual_defined (&lsa->actual))
	*act = &lsa->actual;
      else
	{
	  link_socket_bad_outgoing_addr ();
	  buf->len = 0;
	  *act = NULL;
	}
    }
}

static inline void
link_socket_set_outgoing_addr (const struct buffer *buf,
			       struct link_socket_info *info,
			       const struct link_socket_actual *act,
			       const char *common_name,
			       struct env_set *es)
{
  if (!buf || buf->len > 0)
    {
      struct link_socket_addr *lsa = info->lsa;
      if (
	  /* new or changed address? */
	  (!info->connection_established
	   || !addr_match_proto (&act->dest, &lsa->actual.dest, info->proto))
	  /* address undef or address == remote or --float */
	  && (info->remote_float
	      || !addr_defined (&lsa->remote)
	      || addr_match_proto (&act->dest, &lsa->remote, info->proto))
	  )
	{
	  link_socket_connection_initiated (buf, info, act, common_name, es);
	}
    }
}

/*
 * Stream buffer handling -- stream_buf is a helper class
 * to assist in the packetization of stream transport protocols
 * such as TCP.
 */

void stream_buf_init (struct stream_buf *sb,
		      struct buffer *buf,
		      const unsigned int sockflags,
		      const int proto);

void stream_buf_close (struct stream_buf* sb);
bool stream_buf_added (struct stream_buf *sb, int length_added);

static inline bool
stream_buf_read_setup (struct link_socket* sock)
{
  bool stream_buf_read_setup_dowork (struct link_socket* sock);
  if (link_socket_connection_oriented (sock))
    return stream_buf_read_setup_dowork (sock);
  else
    return true;
}

/*
 * Socket Read Routines
 */

int link_socket_read_tcp (struct link_socket *sock,
			  struct buffer *buf);

#ifdef WIN32

static inline int
link_socket_read_udp_win32 (struct link_socket *sock,
			    struct buffer *buf,
			    struct link_socket_actual *from)
{
  return socket_finalize (sock->sd, &sock->reads, buf, from);
}

#else

int link_socket_read_udp_posix (struct link_socket *sock,
				struct buffer *buf,
				int maxsize,
				struct link_socket_actual *from);

#endif

/* read a TCP or UDP packet from link */
static inline int
link_socket_read (struct link_socket *sock,
		  struct buffer *buf,
		  int maxsize,
		  struct link_socket_actual *from)
{
  if (proto_is_udp(sock->info.proto)) /* unified UDPv4 and UDPv6 */
    {
      int res;

#ifdef WIN32
      res = link_socket_read_udp_win32 (sock, buf, from);
#else
      res = link_socket_read_udp_posix (sock, buf, maxsize, from);
#endif
      return res;
    }
  else if (proto_is_tcp(sock->info.proto)) /* unified TCPv4 and TCPv6 */
    {
      /* from address was returned by accept */
      addr_copy_sa(&from->dest, &sock->info.lsa->actual.dest);
      return link_socket_read_tcp (sock, buf);
    }
  else
    {
      ASSERT (0);
      return -1; /* NOTREACHED */
    }
}

/*
 * Socket Write routines
 */

int link_socket_write_tcp (struct link_socket *sock,
			   struct buffer *buf,
			   struct link_socket_actual *to);

#ifdef WIN32

static inline int
link_socket_write_win32 (struct link_socket *sock,
			 struct buffer *buf,
			 struct link_socket_actual *to)
{
  int err = 0;
  int status = 0;
  if (overlapped_io_active (&sock->writes))
    {
      status = socket_finalize (sock->sd, &sock->writes, NULL, NULL);
      if (status < 0)
	err = WSAGetLastError ();
    }
  socket_send_queue (sock, buf, to);
  if (status < 0)
    {
      WSASetLastError (err);
      return status;
    }
  else
    return BLEN (buf);
}

#else

static inline int
link_socket_write_udp_posix (struct link_socket *sock,
			     struct buffer *buf,
			     struct link_socket_actual *to)
{
#if ENABLE_IP_PKTINFO
  int link_socket_write_udp_posix_sendmsg (struct link_socket *sock,
					   struct buffer *buf,
					   struct link_socket_actual *to);

  if (proto_is_udp(sock->info.proto) && (sock->sockflags & SF_USE_IP_PKTINFO)
	  && addr_defined_ipi(to))
    return link_socket_write_udp_posix_sendmsg (sock, buf, to);
  else
#endif
    return sendto (sock->sd, BPTR (buf), BLEN (buf), 0,
		   (struct sockaddr *) &to->dest.addr.sa,
		   (socklen_t) af_addr_size(to->dest.addr.sa.sa_family));
}

static inline int
link_socket_write_tcp_posix (struct link_socket *sock,
			     struct buffer *buf,
			     struct link_socket_actual *to)
{
  return send (sock->sd, BPTR (buf), BLEN (buf), MSG_NOSIGNAL);
}

#endif

static inline int
link_socket_write_udp (struct link_socket *sock,
		       struct buffer *buf,
		       struct link_socket_actual *to)
{
#ifdef WIN32
  return link_socket_write_win32 (sock, buf, to);
#else
  return link_socket_write_udp_posix (sock, buf, to);
#endif
}

/* write a TCP or UDP packet to link */
static inline int
link_socket_write (struct link_socket *sock,
		   struct buffer *buf,
		   struct link_socket_actual *to)
{
  if (proto_is_udp(sock->info.proto)) /* unified UDPv4 and UDPv6 */
    {
      return link_socket_write_udp (sock, buf, to);
    }
  else if (proto_is_tcp(sock->info.proto)) /* unified TCPv4 and TCPv6 */
    {
      return link_socket_write_tcp (sock, buf, to);
    }
  else
    {
      ASSERT (0);
      return -1; /* NOTREACHED */
    }
}

#if PASSTOS_CAPABILITY

/*
 * Extract TOS bits.  Assumes that ipbuf is a valid IPv4 packet.
 */
static inline void
link_socket_extract_tos (struct link_socket *ls, const struct buffer *ipbuf)
{
  if (ls && ipbuf)
    {
      struct openvpn_iphdr *iph = (struct openvpn_iphdr *) BPTR (ipbuf);
      ls->ptos = iph->tos;
      ls->ptos_defined = true;
    }
}

/*
 * Set socket properties to reflect TOS bits which were extracted
 * from tunnel packet.
 */
static inline void
link_socket_set_tos (struct link_socket *ls)
{
  if (ls && ls->ptos_defined)
    setsockopt (ls->sd, IPPROTO_IP, IP_TOS, (const void *)&ls->ptos, sizeof (ls->ptos));
}

#endif

/*
 * Socket I/O wait functions
 */

static inline bool
socket_read_residual (const struct link_socket *s)
{
  return s && s->stream_buf.residual_fully_formed;
}

static inline event_t
socket_event_handle (const struct link_socket *s)
{
#ifdef WIN32
  return &s->rw_handle;
#else
  return s->sd;
#endif
}

event_t socket_listen_event_handle (struct link_socket *s);

unsigned int
socket_set (struct link_socket *s,
	    struct event_set *es,
	    unsigned int rwflags,
	    void *arg,
	    unsigned int *persistent);

static inline void
socket_set_listen_persistent (struct link_socket *s,
			      struct event_set *es,
			      void *arg)
{
  if (s && !s->listen_persistent_queued)
    {
      event_ctl (es, socket_listen_event_handle (s), EVENT_READ, arg);
      s->listen_persistent_queued = true;
    }
}

static inline void
socket_reset_listen_persistent (struct link_socket *s)
{
#ifdef WIN32
  reset_net_event_win32 (&s->listen_handle, s->sd);
#endif
}

const char *socket_stat (const struct link_socket *s, unsigned int rwflags, struct gc_arena *gc);

#endif /* SOCKET_H */
