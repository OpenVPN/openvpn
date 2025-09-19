/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
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
#include "tun.h"
#include "socket_util.h"

/*
 * OpenVPN's default port number as assigned by IANA.
 */
#define OPENVPN_PORT "1194"

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

/* struct to hold preresolved host names */
struct cached_dns_entry
{
    const char *hostname;
    const char *servname;
    int ai_family;
    unsigned int flags;
    struct addrinfo *ai;
    struct cached_dns_entry *next;
};

/* IP addresses which are persistent across SIGUSR1s */
struct link_socket_addr
{
    struct addrinfo *bind_local;
    struct addrinfo *remote_list;     /* complete remote list */
    struct addrinfo *current_remote;  /* remote used in the
                                       * current connection attempt */
    struct link_socket_actual actual; /* reply to this address */
};

struct link_socket_info
{
    struct link_socket_addr *lsa;
    bool connection_established;
    const char *ipchange_command;
    const struct plugin_list *plugins;
    bool remote_float;
    int proto;       /* Protocol (PROTO_x defined below) */
    sa_family_t af;  /* Address family like AF_INET, AF_INET6 or AF_UNSPEC*/
    bool bind_ipv6_only;
    int mtu_changed; /* Set to true when mtu value is changed */
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
    int len;    /* -1 if not yet known */

    bool error; /* if true, fatal TCP error has occurred,
                 *  requiring that connection be restarted */
#if PORT_SHARE
#define PS_DISABLED 0
#define PS_ENABLED  1
#define PS_FOREIGN  2
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

/**
 * Sets the receive and send buffer sizes of a socket descriptor.
 *
 * @param fd            The socket to modify
 * @param sbs           new sizes.
 * @param reduce_size   apply the new size even if smaller than current one
 */
void socket_set_buffers(socket_descriptor_t fd, const struct socket_buffer_size *sbs,
                        bool reduce_size);

/*
 * This is the main socket structure used by OpenVPN.  The SOCKET_
 * defines try to abstract away our implementation differences between
 * using sockets on Posix vs. Win32.
 */
struct link_socket
{
    struct link_socket_info info;

    struct event_arg ev_arg; /**< this struct will store a pointer to either mi or
                              * link_socket, depending on the event type, to keep
                              * it accessible it's placed within the same struct
                              * it points to. */

    socket_descriptor_t sd;
    socket_descriptor_t ctrl_sd; /* only used for UDP over Socks */

#ifdef _WIN32
    struct overlapped_io reads;
    struct overlapped_io writes;
    struct rw_handle rw_handle;
    struct rw_handle listen_handle; /* For listening on TCP socket in server mode */
#endif

    /* used for printing status info only */
    unsigned int rwflags_debug;

    /* used for long-term queueing of pre-accepted socket listen */
    bool listen_persistent_queued;

    const char *remote_host;
    const char *remote_port;
    const char *local_host;
    const char *local_port;
    struct cached_dns_entry *dns_cache;
    bool bind_local;

#define LS_MODE_DEFAULT         0
#define LS_MODE_TCP_LISTEN      1
#define LS_MODE_TCP_ACCEPT_FROM 2
    int mode;

    int resolve_retry_seconds;
    int mtu_discover_type;

    struct socket_buffer_size socket_buffer_sizes;

    int mtu; /* OS discovered MTU, or 0 if unknown */

#define SF_USE_IP_PKTINFO    (1 << 0)
#define SF_TCP_NODELAY       (1 << 1)
#define SF_PORT_SHARE        (1 << 2)
#define SF_HOST_RANDOMIZE    (1 << 3)
#define SF_GETADDRINFO_DGRAM (1 << 4)
#define SF_DCO_WIN           (1 << 5)
#define SF_PREPEND_SA        (1 << 6)
    unsigned int sockflags;
    int mark;
    const char *bind_dev;

    /* for stream sockets */
    struct stream_buf stream_buf;
    struct buffer stream_buf_data;
    bool stream_reset;

    /* HTTP proxy */
    struct http_proxy_info *http_proxy;

    /* Socks proxy */
    struct socks_proxy_info *socks_proxy;
    struct link_socket_actual socks_relay; /* Socks UDP relay address */

    /* The OpenVPN server we will use the proxy to connect to */
    const char *proxy_dest_host;
    const char *proxy_dest_port;

    /* Pointer to the server-poll to trigger the timeout in function which have
     * their own loop instead of using the main oop */
    struct event_timeout *server_poll_timeout;

#if PASSTOS_CAPABILITY
    /* used to get/set TOS. */
#if defined(TARGET_LINUX)
    uint8_t ptos;
#else /* all the BSDs, Solaris, MacOS use plain "int" -> see "man ip" there */
    int ptos;
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

#ifdef _WIN32

#define openvpn_close_socket(s) closesocket(s)

int socket_recv_queue(struct link_socket *sock, int maxsize);

int socket_send_queue(struct link_socket *sock, struct buffer *buf,
                      const struct link_socket_actual *to);

typedef struct
{
    union
    {
        SOCKET s;
        HANDLE h;
    };
    bool is_handle;
    bool prepend_sa; /* are incoming packets prepended with sockaddr? */
} sockethandle_t;

int sockethandle_finalize(sockethandle_t sh, struct overlapped_io *io, struct buffer *buf,
                          struct link_socket_actual *from);

static inline BOOL
SocketHandleGetOverlappedResult(sockethandle_t sh, struct overlapped_io *io)
{
    return sh.is_handle
               ? GetOverlappedResult(sh.h, &io->overlapped, &io->size, FALSE)
               : WSAGetOverlappedResult(sh.s, &io->overlapped, &io->size, FALSE, &io->flags);
}

static inline int
SocketHandleGetLastError(sockethandle_t sh)
{
    return sh.is_handle ? (int)GetLastError() : WSAGetLastError();
}

inline static void
SocketHandleSetLastError(sockethandle_t sh, DWORD err)
{
    sh.is_handle ? SetLastError(err) : WSASetLastError(err);
}

static inline void
SocketHandleSetInvalError(sockethandle_t sh)
{
    sh.is_handle ? SetLastError(ERROR_INVALID_FUNCTION) : WSASetLastError(WSAEINVAL);
}

#else /* ifdef _WIN32 */

#define openvpn_close_socket(s) close(s)

#endif /* ifdef _WIN32 */

struct link_socket *link_socket_new(void);

void socket_bind(socket_descriptor_t sd, struct addrinfo *local, int af_family, const char *prefix,
                 bool ipv6only);

int openvpn_connect(socket_descriptor_t sd, const struct sockaddr *remote, int connect_timeout,
                    volatile int *signal_received);


/*
 * Initialize link_socket object.
 */
void link_socket_init_phase1(struct context *c, int sock_index, int mode);

void link_socket_init_phase2(struct context *c, struct link_socket *sock);

void do_preresolve(struct context *c);

void link_socket_close(struct link_socket *sock);

void sd_close(socket_descriptor_t *sd);

void bad_address_length(int actual, int expected);

/* IPV4_INVALID_ADDR: returned by link_socket_current_remote()
 * to ease redirect-gateway logic for ipv4 tunnels on ipv6 endpoints
 */
#define IPV4_INVALID_ADDR 0xffffffff
in_addr_t link_socket_current_remote(const struct link_socket_info *info);

const struct in6_addr *link_socket_current_remote_ipv6(const struct link_socket_info *info);

void link_socket_connection_initiated(struct link_socket_info *info,
                                      const struct link_socket_actual *addr,
                                      const char *common_name, struct env_set *es);

void link_socket_bad_incoming_addr(struct buffer *buf, const struct link_socket_info *info,
                                   const struct link_socket_actual *from_addr);

void set_actual_address(struct link_socket_actual *actual, struct addrinfo *ai);

void link_socket_bad_outgoing_addr(void);

void setenv_trusted(struct env_set *es, const struct link_socket_info *info);

bool link_socket_update_flags(struct link_socket *sock, unsigned int sockflags);

void link_socket_update_buffer_sizes(struct link_socket *sock, int rcvbuf, int sndbuf);

/*
 * Low-level functions
 */

socket_descriptor_t create_socket_tcp(struct addrinfo *);

socket_descriptor_t socket_do_accept(socket_descriptor_t sd, struct link_socket_actual *act,
                                     const bool nowait);

#if UNIX_SOCK_SUPPORT

socket_descriptor_t create_socket_unix(void);

void socket_bind_unix(socket_descriptor_t sd, struct sockaddr_un *local, const char *prefix);

socket_descriptor_t socket_accept_unix(socket_descriptor_t sd, struct sockaddr_un *remote);

int socket_connect_unix(socket_descriptor_t sd, struct sockaddr_un *remote);

void sockaddr_unix_init(struct sockaddr_un *local, const char *path);

const char *sockaddr_unix_name(const struct sockaddr_un *local, const char *null);

void socket_delete_unix(const struct sockaddr_un *local);

bool unix_socket_get_peer_uid_gid(const socket_descriptor_t sd, int *uid, int *gid);

#endif /* if UNIX_SOCK_SUPPORT */

static inline bool
link_socket_connection_oriented(const struct link_socket *sock)
{
    if (sock)
    {
        return link_socket_proto_connection_oriented(sock->info.proto);
    }
    else
    {
        return false;
    }
}

#if PORT_SHARE

static inline bool
socket_foreign_protocol_detected(const struct link_socket *sock)
{
    return link_socket_connection_oriented(sock) && sock->stream_buf.port_share_state == PS_FOREIGN;
}

static inline const struct buffer *
socket_foreign_protocol_head(const struct link_socket *sock)
{
    return &sock->stream_buf.buf;
}

static inline int
socket_foreign_protocol_sd(const struct link_socket *sock)
{
    return sock->sd;
}

#endif /* if PORT_SHARE */

static inline bool
socket_connection_reset(const struct link_socket *sock, int status)
{
    if (link_socket_connection_oriented(sock))
    {
        if (sock->stream_reset || sock->stream_buf.error)
        {
            return true;
        }
        else if (status < 0)
        {
            const int err = openvpn_errno();
#ifdef _WIN32
            return err == WSAECONNRESET || err == WSAECONNABORTED
                   || err == ERROR_CONNECTION_ABORTED;
#else
            return err == ECONNRESET;
#endif
        }
    }
    return false;
}

static inline bool
link_socket_verify_incoming_addr(struct buffer *buf, const struct link_socket_info *info,
                                 const struct link_socket_actual *from_addr)
{
    if (buf->len > 0)
    {
        switch (from_addr->dest.addr.sa.sa_family)
        {
            case AF_INET6:
            case AF_INET:
                if (!link_socket_actual_defined(from_addr))
                {
                    return false;
                }
                if (info->remote_float || (!info->lsa->remote_list))
                {
                    return true;
                }
                if (addrlist_match_proto(&from_addr->dest, info->lsa->remote_list, info->proto))
                {
                    return true;
                }
        }
    }
    return false;
}

static inline void
link_socket_get_outgoing_addr(struct buffer *buf, const struct link_socket_info *info,
                              struct link_socket_actual **act)
{
    if (buf->len > 0)
    {
        struct link_socket_addr *lsa = info->lsa;
        if (link_socket_actual_defined(&lsa->actual))
        {
            *act = &lsa->actual;
        }
        else
        {
            link_socket_bad_outgoing_addr();
            buf->len = 0;
            *act = NULL;
        }
    }
}

static inline void
link_socket_set_outgoing_addr(struct link_socket_info *info, const struct link_socket_actual *act,
                              const char *common_name, struct env_set *es)
{
    struct link_socket_addr *lsa = info->lsa;
    if (
        /* new or changed address? */
        (!info->connection_established
         || !addr_match_proto(&act->dest, &lsa->actual.dest, info->proto))
        &&
        /* address undef or address == remote or --float */
        (info->remote_float
         || (!lsa->remote_list || addrlist_match_proto(&act->dest, lsa->remote_list, info->proto))))
    {
        link_socket_connection_initiated(info, act, common_name, es);
    }
}

bool stream_buf_read_setup_dowork(struct link_socket *sock);

static inline bool
stream_buf_read_setup(struct link_socket *sock)
{
    if (link_socket_connection_oriented(sock))
    {
        return stream_buf_read_setup_dowork(sock);
    }
    else
    {
        return true;
    }
}

/**
 * Returns true if we are on Windows and this link is running on DCO-WIN.
 * This helper is used to enable DCO-WIN specific logic that is not relevant
 * to other platforms.
 */
static inline bool
socket_is_dco_win(const struct link_socket *s)
{
    return s->sockflags & SF_DCO_WIN;
}

/*
 * Socket Read Routines
 */

int link_socket_read_tcp(struct link_socket *sock, struct buffer *buf);

#ifdef _WIN32

static inline int
link_socket_read_udp_win32(struct link_socket *sock, struct buffer *buf,
                           struct link_socket_actual *from)
{
    sockethandle_t sh = { .s = sock->sd };
    if (socket_is_dco_win(sock))
    {
        *from = sock->info.lsa->actual;
        sh.is_handle = true;
        sh.prepend_sa = sock->sockflags & SF_PREPEND_SA;
    }
    return sockethandle_finalize(sh, &sock->reads, buf, from);
}

#else  /* ifdef _WIN32 */

int link_socket_read_udp_posix(struct link_socket *sock, struct buffer *buf,
                               struct link_socket_actual *from);

#endif /* ifdef _WIN32 */

/* read a TCP or UDP packet from link */
static inline int
link_socket_read(struct link_socket *sock, struct buffer *buf, struct link_socket_actual *from)
{
    if (proto_is_udp(sock->info.proto) || socket_is_dco_win(sock))
    /* unified UDPv4 and UDPv6, for DCO-WIN the kernel
     * will strip the length header */
    {
        int res;

#ifdef _WIN32
        res = link_socket_read_udp_win32(sock, buf, from);
#else
        res = link_socket_read_udp_posix(sock, buf, from);
#endif
        return res;
    }
    else if (proto_is_tcp(sock->info.proto)) /* unified TCPv4 and TCPv6 */
    {
        /* from address was returned by accept */
        from->dest = sock->info.lsa->actual.dest;
        return link_socket_read_tcp(sock, buf);
    }
    else
    {
        ASSERT(0);
        return -1; /* NOTREACHED */
    }
}

/*
 * Socket Write routines
 */

ssize_t link_socket_write_tcp(struct link_socket *sock, struct buffer *buf,
                              struct link_socket_actual *to);

#ifdef _WIN32

static inline int
link_socket_write_win32(struct link_socket *sock, struct buffer *buf, struct link_socket_actual *to)
{
    int err = 0;
    int status = 0;
    sockethandle_t sh = { .s = sock->sd, .is_handle = socket_is_dco_win(sock) };
    if (overlapped_io_active(&sock->writes))
    {
        status = sockethandle_finalize(sh, &sock->writes, NULL, NULL);
        if (status < 0)
        {
            err = SocketHandleGetLastError(sh);
        }
    }

    /* dco-win mp requires control packets to be prepended with sockaddr */
    if (sock->sockflags & SF_PREPEND_SA)
    {
        if (to->dest.addr.sa.sa_family == AF_INET)
        {
            buf_write_prepend(buf, &to->dest.addr.in4, sizeof(struct sockaddr_in));
        }
        else
        {
            buf_write_prepend(buf, &to->dest.addr.in6, sizeof(struct sockaddr_in6));
        }
    }

    socket_send_queue(sock, buf, to);
    if (status < 0)
    {
        SocketHandleSetLastError(sh, err);
        return status;
    }
    else
    {
        return BLEN(buf);
    }
}

#else /* ifdef _WIN32 */

ssize_t link_socket_write_udp_posix_sendmsg(struct link_socket *sock, struct buffer *buf,
                                            struct link_socket_actual *to);


static inline ssize_t
link_socket_write_udp_posix(struct link_socket *sock, struct buffer *buf,
                            struct link_socket_actual *to)
{
#if ENABLE_IP_PKTINFO
    if (proto_is_udp(sock->info.proto) && (sock->sockflags & SF_USE_IP_PKTINFO)
        && addr_defined_ipi(to))
    {
        return link_socket_write_udp_posix_sendmsg(sock, buf, to);
    }
    else
#endif
        return sendto(sock->sd, BPTR(buf), BLEN(buf), 0, (struct sockaddr *)&to->dest.addr.sa,
                      (socklen_t)af_addr_size(to->dest.addr.sa.sa_family));
}

static inline ssize_t
link_socket_write_tcp_posix(struct link_socket *sock, struct buffer *buf)
{
    return send(sock->sd, BPTR(buf), BLEN(buf), MSG_NOSIGNAL);
}

#endif /* ifdef _WIN32 */

static inline ssize_t
link_socket_write_udp(struct link_socket *sock, struct buffer *buf, struct link_socket_actual *to)
{
#ifdef _WIN32
    return link_socket_write_win32(sock, buf, to);
#else
    return link_socket_write_udp_posix(sock, buf, to);
#endif
}

/* write a TCP or UDP packet to link */
static inline ssize_t
link_socket_write(struct link_socket *sock, struct buffer *buf, struct link_socket_actual *to)
{
    if (proto_is_udp(sock->info.proto) || socket_is_dco_win(sock))
    {
        /* unified UDPv4, UDPv6 and DCO-WIN (driver adds length header) */
        return link_socket_write_udp(sock, buf, to);
    }
    else if (proto_is_tcp(sock->info.proto)) /* unified TCPv4 and TCPv6 */
    {
        return link_socket_write_tcp(sock, buf, to);
    }
    else
    {
        ASSERT(0);
        return -1; /* NOTREACHED */
    }
}

#if PASSTOS_CAPABILITY

/*
 * Extract TOS bits.  Assumes that ipbuf is a valid IPv4 packet.
 */
static inline void
link_socket_extract_tos(struct link_socket *sock, const struct buffer *ipbuf)
{
    if (sock && ipbuf)
    {
        struct openvpn_iphdr *iph = (struct openvpn_iphdr *)BPTR(ipbuf);
        sock->ptos = iph->tos;
        sock->ptos_defined = true;
    }
}

/*
 * Set socket properties to reflect TOS bits which were extracted
 * from tunnel packet.
 */
static inline void
link_socket_set_tos(struct link_socket *sock)
{
    if (sock && sock->ptos_defined)
    {
        setsockopt(sock->sd, IPPROTO_IP, IP_TOS, (const void *)&sock->ptos, sizeof(sock->ptos));
    }
}

#endif /* if PASSTOS_CAPABILITY */

/*
 * Socket I/O wait functions
 */

/*
 * Extends the pre-existing read residual logic
 * to all initialized sockets, ensuring the complete
 * packet is read.
 */
bool sockets_read_residual(const struct context *c);

static inline event_t
socket_event_handle(const struct link_socket *sock)
{
#ifdef _WIN32
    return &sock->rw_handle;
#else
    return sock->sd;
#endif
}

event_t socket_listen_event_handle(struct link_socket *sock);

unsigned int socket_set(struct link_socket *sock, struct event_set *es, unsigned int rwflags,
                        void *arg, unsigned int *persistent);

static inline void
socket_set_listen_persistent(struct link_socket *sock, struct event_set *es, void *arg)
{
    if (sock && !sock->listen_persistent_queued)
    {
        event_ctl(es, socket_listen_event_handle(sock), EVENT_READ, arg);
        sock->listen_persistent_queued = true;
    }
}

static inline void
socket_reset_listen_persistent(struct link_socket *sock)
{
#ifdef _WIN32
    reset_net_event_win32(&sock->listen_handle, sock->sd);
#endif
}

const char *socket_stat(const struct link_socket *sock, unsigned int rwflags, struct gc_arena *gc);

#endif /* SOCKET_H */
