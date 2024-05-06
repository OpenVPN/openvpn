/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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

/*
 * 2004-01-30: Added Socks5 proxy support, see RFC 1928
 *   (Christof Meerwald, http://cmeerw.org)
 *
 * 2010-10-10: Added Socks5 plain text authentication support (RFC 1929)
 *   (Pierre Bourdon <delroth@gmail.com>)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "common.h"
#include "misc.h"
#include "win32.h"
#include "socket.h"
#include "fdmisc.h"
#include "misc.h"
#include "proxy.h"

#include "memdbg.h"

#define UP_TYPE_SOCKS           "SOCKS Proxy"

struct socks_proxy_info *
socks_proxy_new(const char *server,
                const char *port,
                const char *authfile)
{
    struct socks_proxy_info *p;

    ALLOC_OBJ_CLEAR(p, struct socks_proxy_info);

    ASSERT(server);
    ASSERT(port);

    strncpynt(p->server, server, sizeof(p->server));
    p->port = port;

    if (authfile)
    {
        strncpynt(p->authfile, authfile, sizeof(p->authfile));
    }
    else
    {
        p->authfile[0] = 0;
    }

    p->defined = true;

    return p;
}

void
socks_proxy_close(struct socks_proxy_info *sp)
{
    free(sp);
}

static bool
socks_username_password_auth(struct socks_proxy_info *p,
                             socket_descriptor_t sd,
                             volatile int *signal_received)
{
    char to_send[516];
    char buf[2];
    int len = 0;
    const int timeout_sec = 5;
    struct user_pass creds;
    ssize_t size;
    bool ret = false;

    creds.defined = 0;
    if (!get_user_pass(&creds, p->authfile, UP_TYPE_SOCKS, GET_USER_PASS_MANAGEMENT))
    {
        msg(M_NONFATAL, "SOCKS failed to get username/password.");
        goto cleanup;
    }

    if ( (strlen(creds.username) > 255) || (strlen(creds.password) > 255) )
    {
        msg(M_NONFATAL,
            "SOCKS username and/or password exceeds 255 characters.  "
            "Authentication not possible.");
        goto cleanup;
    }

    int sret = snprintf(to_send, sizeof(to_send), "\x01%c%s%c%s",
                        (int) strlen(creds.username), creds.username,
                        (int) strlen(creds.password), creds.password);
    ASSERT(sret <= sizeof(to_send));

    size = send(sd, to_send, strlen(to_send), MSG_NOSIGNAL);

    if (size != strlen(to_send))
    {
        msg(D_LINK_ERRORS | M_ERRNO, "socks_username_password_auth: TCP port write failed on send()");
        goto cleanup;
    }

    while (len < 2)
    {
        int status;
        ssize_t size;
        fd_set reads;
        struct timeval tv;
        char c;

        FD_ZERO(&reads);
        openvpn_fd_set(sd, &reads);
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;

        status = select(sd + 1, &reads, NULL, NULL, &tv);

        get_signal(signal_received);
        if (*signal_received)
        {
            goto cleanup;
        }

        /* timeout? */
        if (status == 0)
        {
            msg(D_LINK_ERRORS | M_ERRNO, "socks_username_password_auth: TCP port read timeout expired");
            goto cleanup;
        }

        /* error */
        if (status < 0)
        {
            msg(D_LINK_ERRORS | M_ERRNO, "socks_username_password_auth: TCP port read failed on select()");
            goto cleanup;
        }

        /* read single char */
        size = recv(sd, &c, 1, MSG_NOSIGNAL);

        /* error? */
        if (size != 1)
        {
            msg(D_LINK_ERRORS | M_ERRNO, "socks_username_password_auth: TCP port read failed on recv()");
            goto cleanup;
        }

        /* store char in buffer */
        buf[len++] = c;
    }

    /* VER = 5, SUCCESS = 0 --> auth success */
    if (buf[0] != 5 && buf[1] != 0)
    {
        msg(D_LINK_ERRORS, "socks_username_password_auth: server refused the authentication");
        goto cleanup;
    }

    ret = true;
cleanup:
    secure_memzero(&creds, sizeof(creds));
    secure_memzero(to_send, sizeof(to_send));
    return ret;
}

static bool
socks_handshake(struct socks_proxy_info *p,
                socket_descriptor_t sd,
                volatile int *signal_received)
{
    char buf[2];
    int len = 0;
    const int timeout_sec = 5;
    ssize_t size;

    /* VER = 5, NMETHODS = 1, METHODS = [0 (no auth)] */
    char method_sel[3] = { 0x05, 0x01, 0x00 };
    if (p->authfile[0])
    {
        method_sel[2] = 0x02; /* METHODS = [2 (plain login)] */

    }
    size = send(sd, method_sel, sizeof(method_sel), MSG_NOSIGNAL);
    if (size != sizeof(method_sel))
    {
        msg(D_LINK_ERRORS | M_ERRNO, "socks_handshake: TCP port write failed on send()");
        return false;
    }

    while (len < 2)
    {
        int status;
        ssize_t size;
        fd_set reads;
        struct timeval tv;
        char c;

        FD_ZERO(&reads);
        openvpn_fd_set(sd, &reads);
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;

        status = select(sd + 1, &reads, NULL, NULL, &tv);

        get_signal(signal_received);
        if (*signal_received)
        {
            return false;
        }

        /* timeout? */
        if (status == 0)
        {
            msg(D_LINK_ERRORS | M_ERRNO, "socks_handshake: TCP port read timeout expired");
            return false;
        }

        /* error */
        if (status < 0)
        {
            msg(D_LINK_ERRORS | M_ERRNO, "socks_handshake: TCP port read failed on select()");
            return false;
        }

        /* read single char */
        size = recv(sd, &c, 1, MSG_NOSIGNAL);

        /* error? */
        if (size != 1)
        {
            msg(D_LINK_ERRORS | M_ERRNO, "socks_handshake: TCP port read failed on recv()");
            return false;
        }

        /* store char in buffer */
        buf[len++] = c;
    }

    /* VER == 5 */
    if (buf[0] != '\x05')
    {
        msg(D_LINK_ERRORS, "socks_handshake: Socks proxy returned bad status");
        return false;
    }

    /* validate that the auth method returned is the one sent */
    if (buf[1] != method_sel[2])
    {
        msg(D_LINK_ERRORS, "socks_handshake: Socks proxy returned unexpected auth");
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
            {
                return false;
            }

            break;

        default: /* unknown auth method */
            msg(D_LINK_ERRORS, "socks_handshake: unknown SOCKS auth method");
            return false;
    }

    return true;
}

static bool
recv_socks_reply(socket_descriptor_t sd,
                 struct openvpn_sockaddr *addr,
                 volatile int *signal_received)
{
    char atyp = '\0';
    int alen = 0;
    int len = 0;
    char buf[270];              /* 4 + alen(max 256) + 2 */
    const int timeout_sec = 5;

    if (addr != NULL)
    {
        addr->addr.in4.sin_family = AF_INET;
        addr->addr.in4.sin_addr.s_addr = htonl(INADDR_ANY);
        addr->addr.in4.sin_port = htons(0);
    }

    while (len < 4 + alen + 2)
    {
        int status;
        ssize_t size;
        fd_set reads;
        struct timeval tv;
        char c;

        FD_ZERO(&reads);
        openvpn_fd_set(sd, &reads);
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;

        status = select(sd + 1, &reads, NULL, NULL, &tv);

        get_signal(signal_received);
        if (*signal_received)
        {
            return false;
        }

        /* timeout? */
        if (status == 0)
        {
            msg(D_LINK_ERRORS | M_ERRNO, "recv_socks_reply: TCP port read timeout expired");
            return false;
        }

        /* error */
        if (status < 0)
        {
            msg(D_LINK_ERRORS | M_ERRNO, "recv_socks_reply: TCP port read failed on select()");
            return false;
        }

        /* read single char */
        size = recv(sd, &c, 1, MSG_NOSIGNAL);

        /* error? */
        if (size < 0)
        {
            msg(D_LINK_ERRORS | M_ERRNO, "recv_socks_reply: TCP port read failed on recv()");
            return false;
        }
        else if (size == 0)
        {
            msg(D_LINK_ERRORS, "ERROR: recv_socks_reply: empty response from socks server");
            return false;
        }

        if (len == 3)
        {
            atyp = c;
        }

        if (len == 4)
        {
            switch (atyp)
            {
                case '\x01':    /* IP V4 */
                    alen = 4;
                    break;

                case '\x03':    /* DOMAINNAME */
                    /* RFC 1928, section 5: 1 byte length, <n> bytes name,
                     * so the total "address length" is (length+1)
                     */
                    alen = (unsigned char) c + 1;
                    break;

                case '\x04':    /* IP V6 */
                    alen = 16;
                    break;

                default:
                    msg(D_LINK_ERRORS, "recv_socks_reply: Socks proxy returned bad address type");
                    return false;
            }
        }

        /* store char in buffer */
        if (len < (int)sizeof(buf))
        {
            buf[len] = c;
        }
        ++len;
    }

    /* VER == 5 && REP == 0 (succeeded) */
    if (buf[0] != '\x05' || buf[1] != '\x00')
    {
        msg(D_LINK_ERRORS, "recv_socks_reply: Socks proxy returned bad reply");
        return false;
    }

    /* ATYP == 1 (IP V4 address) */
    if (atyp == '\x01' && addr != NULL)
    {
        memcpy(&addr->addr.in4.sin_addr, buf + 4, sizeof(addr->addr.in4.sin_addr));
        memcpy(&addr->addr.in4.sin_port, buf + 8, sizeof(addr->addr.in4.sin_port));
        struct gc_arena gc = gc_new();
        msg(M_INFO, "SOCKS proxy wants us to send UDP to %s",
            print_openvpn_sockaddr(addr, &gc));
        gc_free(&gc);
    }


    return true;
}

static int
port_from_servname(const char *servname)
{
    int port = 0;
    port = atoi(servname);
    if (port >0 && port < 65536)
    {
        return port;
    }

    struct  servent *service;
    service = getservbyname(servname, NULL);
    if (service)
    {
        return service->s_port;
    }

    return 0;
}

void
establish_socks_proxy_passthru(struct socks_proxy_info *p,
                               socket_descriptor_t sd,  /* already open to proxy */
                               const char *host,        /* openvpn server remote */
                               const char *servname,    /* openvpn server port */
                               struct signal_info *sig_info)
{
    char buf[270];
    size_t len;

    if (!socks_handshake(p, sd, &sig_info->signal_received))
    {
        goto error;
    }

    /* format Socks CONNECT message */
    buf[0] = '\x05';            /* VER = 5 */
    buf[1] = '\x01';            /* CMD = 1 (CONNECT) */
    buf[2] = '\x00';            /* RSV */
    buf[3] = '\x03';            /* ATYP = 3 (DOMAINNAME) */

    len = strlen(host);
    len = (5 + len + 2 > sizeof(buf)) ? (sizeof(buf) - 5 - 2) : len;

    buf[4] = (char) len;
    memcpy(buf + 5, host, len);

    int port = port_from_servname(servname);
    if (port ==0)
    {
        msg(D_LINK_ERRORS, "establish_socks_proxy_passthrough: Cannot convert %s to port number", servname);
        goto error;
    }

    buf[5 + len] = (char) (port >> 8);
    buf[5 + len + 1] = (char) (port & 0xff);

    {
        const ssize_t size = send(sd, buf, 5 + len + 2, MSG_NOSIGNAL);
        if ((int)size != 5 + (int)len + 2)
        {
            msg(D_LINK_ERRORS | M_ERRNO, "establish_socks_proxy_passthru: TCP port write failed on send()");
            goto error;
        }
    }


    /* receive reply from Socks proxy and discard */
    if (!recv_socks_reply(sd, NULL, &sig_info->signal_received))
    {
        goto error;
    }

    return;

error:
    /* SOFT-SIGUSR1 -- socks error */
    register_signal(sig_info, SIGUSR1, "socks-error");
    return;
}

void
establish_socks_proxy_udpassoc(struct socks_proxy_info *p,
                               socket_descriptor_t ctrl_sd,  /* already open to proxy */
                               socket_descriptor_t udp_sd,
                               struct openvpn_sockaddr *relay_addr,
                               struct signal_info *sig_info)
{
    if (!socks_handshake(p, ctrl_sd, &sig_info->signal_received))
    {
        goto error;
    }

    {
        /* send Socks UDP ASSOCIATE message */
        /* VER = 5, CMD = 3 (UDP ASSOCIATE), RSV = 0, ATYP = 1 (IP V4),
         * BND.ADDR = 0, BND.PORT = 0 */
        const ssize_t size = send(ctrl_sd,
                                  "\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00",
                                  10, MSG_NOSIGNAL);
        if (size != 10)
        {
            msg(D_LINK_ERRORS | M_ERRNO, "establish_socks_proxy_passthru: TCP port write failed on send()");
            goto error;
        }
    }

    /* receive reply from Socks proxy */
    CLEAR(*relay_addr);
    if (!recv_socks_reply(ctrl_sd, relay_addr, &sig_info->signal_received))
    {
        goto error;
    }

    return;

error:
    /* SOFT-SIGUSR1 -- socks error */
    register_signal(sig_info, SIGUSR1, "socks-error");
    return;
}

/*
 * Remove the 10 byte socks5 header from an incoming
 * UDP packet, setting *from to the source address.
 *
 * Run after UDP read.
 */
void
socks_process_incoming_udp(struct buffer *buf,
                           struct link_socket_actual *from)
{
    int atyp;

    if (BLEN(buf) < 10)
    {
        goto error;
    }

    buf_read_u16(buf);
    if (buf_read_u8(buf) != 0)
    {
        goto error;
    }

    atyp = buf_read_u8(buf);
    if (atyp != 1)              /* ATYP == 1 (IP V4) */
    {
        goto error;
    }

    buf_read(buf, &from->dest.addr.in4.sin_addr, sizeof(from->dest.addr.in4.sin_addr));
    buf_read(buf, &from->dest.addr.in4.sin_port, sizeof(from->dest.addr.in4.sin_port));

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
socks_process_outgoing_udp(struct buffer *buf,
                           const struct link_socket_actual *to)
{
    /*
     * Get a 10 byte subset buffer prepended to buf --
     * we expect these bytes will be here because
     * we always allocate space for these bytes
     */
    struct buffer head = buf_sub(buf, 10, true);

    /* crash if not enough headroom in buf */
    ASSERT(buf_defined(&head));

    buf_write_u16(&head, 0);    /* RSV = 0 */
    buf_write_u8(&head, 0);     /* FRAG = 0 */
    buf_write_u8(&head, '\x01'); /* ATYP = 1 (IP V4) */
    buf_write(&head, &to->dest.addr.in4.sin_addr, sizeof(to->dest.addr.in4.sin_addr));
    buf_write(&head, &to->dest.addr.in4.sin_port, sizeof(to->dest.addr.in4.sin_port));

    return 10;
}
