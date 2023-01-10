/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if PORT_SHARE

#include "event.h"
#include "socket.h"
#include "fdmisc.h"
#include "crypto.h"
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

/*
 * Return values for proxy_connection_io functions
 */

#define IOSTAT_EAGAIN_ON_READ   0 /* recv returned EAGAIN */
#define IOSTAT_EAGAIN_ON_WRITE  1 /* send returned EAGAIN */
#define IOSTAT_READ_ERROR       2 /* the other end of our read socket (pc) was closed */
#define IOSTAT_WRITE_ERROR      3 /* the other end of our write socket (pc->counterpart) was closed */
#define IOSTAT_GOOD             4 /* nothing to report */

/*
 * A foreign (non-OpenVPN) connection we are proxying,
 * usually HTTPS
 */
struct proxy_connection {
    bool defined;
    struct proxy_connection *next;
    struct proxy_connection *counterpart;
    struct buffer buf;
    bool buffer_initial;
    int rwflags;
    int sd;
    char *jfn;
};

#if 0
static const char *
headc(const struct buffer *buf)
{
    static char foo[16];
    strncpy(foo, BSTR(buf), 15);
    foo[15] = 0;
    return foo;
}
#endif

static inline void
close_socket_if_defined(const socket_descriptor_t sd)
{
    if (socket_defined(sd))
    {
        openvpn_close_socket(sd);
    }
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
close_fds_except(int keep)
{
    socket_descriptor_t i;
    closelog();
    for (i = 3; i <= 100; ++i)
    {
        if (i != keep)
        {
            openvpn_close_socket(i);
        }
    }
}

/*
 * Usually we ignore signals, because our parent will
 * deal with them.
 */
static void
set_signals(void)
{
    signal(SIGTERM, SIG_DFL);

    signal(SIGINT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGUSR1, SIG_IGN);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
}

/*
 * Socket read/write functions.
 */

static int
recv_control(const socket_descriptor_t fd)
{
    unsigned char c;
    const ssize_t size = read(fd, &c, sizeof(c));
    if (size == sizeof(c))
    {
        return c;
    }
    else
    {
        return -1;
    }
}

static int
send_control(const socket_descriptor_t fd, int code)
{
    unsigned char c = (unsigned char) code;
    const ssize_t size = write(fd, &c, sizeof(c));
    if (size == sizeof(c))
    {
        return (int) size;
    }
    else
    {
        return -1;
    }
}

static int
cmsg_size(void)
{
    return CMSG_SPACE(sizeof(socket_descriptor_t));
}

/*
 * Send a command (char), data (head), and a file descriptor (sd_send) to a local process
 * over unix socket sd.  Unfortunately, there's no portable way to send file descriptors
 * to other processes, so this code, as well as its analog (control_message_from_parent below),
 * is Linux-specific. This function runs in the context of the main process and is used to
 * send commands, data, and file descriptors to the background process.
 */
static void
port_share_sendmsg(const socket_descriptor_t sd,
                   const char command,
                   const struct buffer *head,
                   const socket_descriptor_t sd_send)
{
    if (socket_defined(sd))
    {
        struct msghdr mesg;
        struct cmsghdr *h;
        struct iovec iov[2];
        socket_descriptor_t sd_null[2] = { SOCKET_UNDEFINED, SOCKET_UNDEFINED };
        char cmd;
        ssize_t status;

        dmsg(D_PS_PROXY_DEBUG, "PORT SHARE: sendmsg sd=%d len=%d",
             (int)sd_send,
             head ? BLEN(head) : -1);

        CLEAR(mesg);

        cmd = command;

        iov[0].iov_base = &cmd;
        iov[0].iov_len = sizeof(cmd);
        mesg.msg_iovlen = 1;

        if (head)
        {
            iov[1].iov_base = BPTR(head);
            iov[1].iov_len = BLEN(head);
            mesg.msg_iovlen = 2;
        }

        mesg.msg_iov = iov;

        mesg.msg_controllen = cmsg_size();
        mesg.msg_control = (char *) malloc(mesg.msg_controllen);
        check_malloc_return(mesg.msg_control);
        mesg.msg_flags = 0;

        h = CMSG_FIRSTHDR(&mesg);
        h->cmsg_level = SOL_SOCKET;
        h->cmsg_type = SCM_RIGHTS;
        h->cmsg_len = CMSG_LEN(sizeof(socket_descriptor_t));

        if (socket_defined(sd_send))
        {
            memcpy(CMSG_DATA(h), &sd_send, sizeof(sd_send));
        }
        else
        {
            socketpair(PF_UNIX, SOCK_DGRAM, 0, sd_null);
            memcpy(CMSG_DATA(h), &sd_null[0], sizeof(sd_null[0]));
        }

        status = sendmsg(sd, &mesg, MSG_NOSIGNAL);
        if (status == -1)
        {
            msg(M_WARN|M_ERRNO, "PORT SHARE: sendmsg failed -- unable to communicate with background process (%d,%d,%d,%d)",
                sd, sd_send, sd_null[0], sd_null[1]
                );
        }

        close_socket_if_defined(sd_null[0]);
        close_socket_if_defined(sd_null[1]);
        free(mesg.msg_control);
    }
}

static void
proxy_entry_close_sd(struct proxy_connection *pc, struct event_set *es)
{
    if (pc->defined && socket_defined(pc->sd))
    {
        dmsg(D_PS_PROXY_DEBUG, "PORT SHARE PROXY: delete sd=%d", (int)pc->sd);
        if (es)
        {
            event_del(es, pc->sd);
        }
        openvpn_close_socket(pc->sd);
        pc->sd = SOCKET_UNDEFINED;
    }
}

/*
 * Mark a proxy entry and its counterpart for close.
 */
static void
proxy_entry_mark_for_close(struct proxy_connection *pc, struct event_set *es)
{
    if (pc->defined)
    {
        struct proxy_connection *cp = pc->counterpart;
        proxy_entry_close_sd(pc, es);
        free_buf(&pc->buf);
        pc->buffer_initial = false;
        pc->rwflags = 0;
        pc->defined = false;
        if (pc->jfn)
        {
            unlink(pc->jfn);
            free(pc->jfn);
            pc->jfn = NULL;
        }
        if (cp && cp->defined && cp->counterpart == pc)
        {
            proxy_entry_mark_for_close(cp, es);
        }
    }
}

/*
 * Run through the proxy entry list and delete all entries marked
 * for close.
 */
static void
proxy_list_housekeeping(struct proxy_connection **list)
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
                free(pc);
                if (prev)
                {
                    prev->next = next;
                }
                else
                {
                    *list = next;
                }
            }
            else
            {
                prev = pc;
            }
            pc = next;
        }
    }
}

/*
 * Record IP/port of client in filesystem, so that server receiving
 * the proxy can determine true client origin.
 */
static void
journal_add(const char *journal_dir, struct proxy_connection *pc, struct proxy_connection *cp)
{
    struct gc_arena gc = gc_new();
    struct openvpn_sockaddr from, to;
    socklen_t slen, dlen;
    int fnlen;
    char *jfn;
    int fd;

    slen = sizeof(from.addr.sa);
    dlen = sizeof(to.addr.sa);
    if (!getpeername(pc->sd, (struct sockaddr *) &from.addr.sa, &slen)
        && !getsockname(cp->sd, (struct sockaddr *) &to.addr.sa, &dlen))
    {
        const char *f = print_openvpn_sockaddr(&from, &gc);
        const char *t = print_openvpn_sockaddr(&to, &gc);
        fnlen =  strlen(journal_dir) + strlen(t) + 2;
        jfn = (char *) malloc(fnlen);
        check_malloc_return(jfn);
        openvpn_snprintf(jfn, fnlen, "%s/%s", journal_dir, t);
        dmsg(D_PS_PROXY_DEBUG, "PORT SHARE PROXY: client origin %s -> %s", jfn, f);
        fd = platform_open(jfn, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP);
        if (fd != -1)
        {
            if (write(fd, f, strlen(f)) != strlen(f))
            {
                msg(M_WARN, "PORT SHARE: writing to journal file (%s) failed", jfn);
            }
            close(fd);
            cp->jfn = jfn;
        }
        else
        {
            msg(M_WARN|M_ERRNO, "PORT SHARE: unable to write journal file in %s", jfn);
            free(jfn);
        }
    }
    gc_free(&gc);
}

/*
 * Cleanup function, on proxy process exit.
 */
static void
proxy_list_close(struct proxy_connection **list)
{
    if (list)
    {
        struct proxy_connection *pc = *list;
        while (pc)
        {
            proxy_entry_mark_for_close(pc, NULL);
            pc = pc->next;
        }
        proxy_list_housekeeping(list);
    }
}

static inline void
proxy_connection_io_requeue(struct proxy_connection *pc, const int rwflags_new, struct event_set *es)
{
    if (socket_defined(pc->sd) && pc->rwflags != rwflags_new)
    {
        /*dmsg (D_PS_PROXY_DEBUG, "PORT SHARE PROXY: requeue[%d] rwflags=%d", (int)pc->sd, rwflags_new);*/
        event_ctl(es, pc->sd, rwflags_new, (void *)pc);
        pc->rwflags = rwflags_new;
    }
}

/*
 * Create a new pair of proxy_connection entries, one for each
 * socket file descriptor involved in the proxy.  We are given
 * the client fd, and we should derive our own server fd by connecting
 * to the server given by server_addr/server_port.  Return true
 * on success and false on failure to connect to server.
 */
static bool
proxy_entry_new(struct proxy_connection **list,
                struct event_set *es,
                const struct sockaddr_in server_addr,
                const socket_descriptor_t sd_client,
                struct buffer *initial_data,
                const char *journal_dir)
{
    socket_descriptor_t sd_server;
    int status;
    struct proxy_connection *pc;
    struct proxy_connection *cp;

    /* connect to port share server */
    if ((sd_server = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        msg(M_WARN|M_ERRNO, "PORT SHARE PROXY: cannot create socket");
        return false;
    }
    status = openvpn_connect(sd_server, (const struct sockaddr *)  &server_addr, 5, NULL);
    if (status)
    {
        msg(M_WARN, "PORT SHARE PROXY: connect to port-share server failed");
        openvpn_close_socket(sd_server);
        return false;
    }
    dmsg(D_PS_PROXY_DEBUG, "PORT SHARE PROXY: connect to port-share server succeeded");

    set_nonblock(sd_client);
    set_nonblock(sd_server);

    /* allocate 2 new proxy_connection objects */
    ALLOC_OBJ_CLEAR(pc, struct proxy_connection);
    ALLOC_OBJ_CLEAR(cp, struct proxy_connection);

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
    cp->buf = alloc_buf(PROXY_CONNECTION_BUFFER_SIZE);
    cp->buffer_initial = false;
    cp->rwflags = EVENT_UNDEF;
    cp->sd = sd_server;

    /* add to list */
    *list = pc;

    /* add journal entry */
    if (journal_dir)
    {
        journal_add(journal_dir, pc, cp);
    }

    dmsg(D_PS_PROXY_DEBUG, "PORT SHARE PROXY: NEW CONNECTION [c=%d s=%d]", (int)sd_client, (int)sd_server);

    /* set initial i/o states */
    proxy_connection_io_requeue(pc, EVENT_READ, es);
    proxy_connection_io_requeue(cp, EVENT_READ|EVENT_WRITE, es);

    return true;
}

/*
 * This function runs in the context of the background proxy process.
 * Receive a control message from the parent (sent by the port_share_sendmsg
 * function above) and act on it.  Return false if the proxy process should
 * exit, true otherwise.
 */
static bool
control_message_from_parent(const socket_descriptor_t sd_control,
                            struct proxy_connection **list,
                            struct event_set *es,
                            const struct sockaddr_in server_addr,
                            const int max_initial_buf,
                            const char *journal_dir)
{
    /* this buffer needs to be large enough to handle the largest buffer
     * that might be returned by the link_socket_read call in read_incoming_link. */
    struct buffer buf = alloc_buf(max_initial_buf);

    struct msghdr mesg;
    struct cmsghdr *h;
    struct iovec iov[2];
    char command = 0;
    ssize_t status;
    int ret = true;

    CLEAR(mesg);

    iov[0].iov_base = &command;
    iov[0].iov_len = sizeof(command);
    iov[1].iov_base = BPTR(&buf);
    iov[1].iov_len = BCAP(&buf);
    mesg.msg_iov = iov;
    mesg.msg_iovlen = 2;

    mesg.msg_controllen = cmsg_size();
    mesg.msg_control = (char *) malloc(mesg.msg_controllen);
    check_malloc_return(mesg.msg_control);
    mesg.msg_flags = 0;

    h = CMSG_FIRSTHDR(&mesg);
    h->cmsg_len = CMSG_LEN(sizeof(socket_descriptor_t));
    h->cmsg_level = SOL_SOCKET;
    h->cmsg_type = SCM_RIGHTS;
    static const socket_descriptor_t socket_undefined = SOCKET_UNDEFINED;
    memcpy(CMSG_DATA(h), &socket_undefined, sizeof(socket_undefined));

    status = recvmsg(sd_control, &mesg, MSG_NOSIGNAL);
    if (status != -1)
    {
        if (h == NULL
            || h->cmsg_len    != CMSG_LEN(sizeof(socket_descriptor_t))
            || h->cmsg_level  != SOL_SOCKET
            || h->cmsg_type   != SCM_RIGHTS)
        {
            msg(M_WARN, "PORT SHARE PROXY: received unknown message");
        }
        else
        {
            socket_descriptor_t received_fd;
            memcpy(&received_fd, CMSG_DATA(h), sizeof(received_fd));
            dmsg(D_PS_PROXY_DEBUG, "PORT SHARE PROXY: RECEIVED sd=%d", (int)received_fd);

            if (status >= 2 && command == COMMAND_REDIRECT)
            {
                buf.len = status - 1;
                if (proxy_entry_new(list,
                                    es,
                                    server_addr,
                                    received_fd,
                                    &buf,
                                    journal_dir))
                {
                    CLEAR(buf); /* we gave the buffer to proxy_entry_new */
                }
                else
                {
                    openvpn_close_socket(received_fd);
                }
            }
            else if (status >= 1 && command == COMMAND_EXIT)
            {
                dmsg(D_PS_PROXY_DEBUG, "PORT SHARE PROXY: RECEIVED COMMAND_EXIT");
                openvpn_close_socket(received_fd); /* null socket */
                ret = false;
            }
        }
    }
    free(mesg.msg_control);
    free_buf(&buf);
    return ret;
}

static int
proxy_connection_io_recv(struct proxy_connection *pc)
{
    /* recv data from socket */
    const int status = recv(pc->sd, BPTR(&pc->buf), BCAP(&pc->buf), MSG_NOSIGNAL);
    if (status < 0)
    {
        return (errno == EAGAIN) ? IOSTAT_EAGAIN_ON_READ : IOSTAT_READ_ERROR;
    }
    else
    {
        if (!status)
        {
            return IOSTAT_READ_ERROR;
        }
        dmsg(D_PS_PROXY_DEBUG, "PORT SHARE PROXY: read[%d] %d", (int)pc->sd, status);
        pc->buf.len = status;
    }
    return IOSTAT_GOOD;
}

static int
proxy_connection_io_send(struct proxy_connection *pc, int *bytes_sent)
{
    const socket_descriptor_t sd = pc->counterpart->sd;
    const int status = send(sd, BPTR(&pc->buf), BLEN(&pc->buf), MSG_NOSIGNAL);

    if (status < 0)
    {
        const int e = errno;
        return (e == EAGAIN) ? IOSTAT_EAGAIN_ON_WRITE : IOSTAT_WRITE_ERROR;
    }
    else
    {
        *bytes_sent += status;
        if (status != pc->buf.len)
        {
            dmsg(D_PS_PROXY_DEBUG, "PORT SHARE PROXY: partial write[%d], tried=%d got=%d", (int)sd, pc->buf.len, status);
            buf_advance(&pc->buf, status);
            return IOSTAT_EAGAIN_ON_WRITE;
        }
        else
        {
            dmsg(D_PS_PROXY_DEBUG, "PORT SHARE PROXY: wrote[%d] %d", (int)sd, status);
            pc->buf.len = 0;
            pc->buf.offset = 0;
        }
    }

    /* realloc send buffer after initial send */
    if (pc->buffer_initial)
    {
        free_buf(&pc->buf);
        pc->buf = alloc_buf(PROXY_CONNECTION_BUFFER_SIZE);
        pc->buffer_initial = false;
    }
    return IOSTAT_GOOD;
}

/*
 * Forward data from pc to pc->counterpart.
 */

static int
proxy_connection_io_xfer(struct proxy_connection *pc, const int max_transfer)
{
    int transferred = 0;
    while (transferred < max_transfer)
    {
        if (!BLEN(&pc->buf))
        {
            const int status = proxy_connection_io_recv(pc);
            if (status != IOSTAT_GOOD)
            {
                return status;
            }
        }

        if (BLEN(&pc->buf))
        {
            const int status = proxy_connection_io_send(pc, &transferred);
            if (status != IOSTAT_GOOD)
            {
                return status;
            }
        }
    }
    return IOSTAT_EAGAIN_ON_READ;
}

/*
 * Decide how the receipt of an EAGAIN status should affect our next IO queueing.
 */
static bool
proxy_connection_io_status(const int status, int *rwflags_pc, int *rwflags_cp)
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

        case IOSTAT_READ_ERROR:
            return false;

        case IOSTAT_WRITE_ERROR:
            return false;

        default:
            msg(M_FATAL, "PORT SHARE PROXY: unexpected status=%d", status);
    }
    return false; /* NOTREACHED */
}

/*
 * Dispatch function for forwarding data between the two socket fds involved
 * in the proxied connection.
 */
static int
proxy_connection_io_dispatch(struct proxy_connection *pc,
                             const int rwflags,
                             struct event_set *es)
{
    const int max_transfer_per_iteration = 10000;
    struct proxy_connection *cp = pc->counterpart;
    int rwflags_pc = pc->rwflags;
    int rwflags_cp = cp->rwflags;

    ASSERT(pc->defined && cp->defined && cp->counterpart == pc);

    if (rwflags & EVENT_READ)
    {
        const int status = proxy_connection_io_xfer(pc, max_transfer_per_iteration);
        if (!proxy_connection_io_status(status, &rwflags_pc, &rwflags_cp))
        {
            goto bad;
        }
    }
    if (rwflags & EVENT_WRITE)
    {
        const int status = proxy_connection_io_xfer(cp, max_transfer_per_iteration);
        if (!proxy_connection_io_status(status, &rwflags_cp, &rwflags_pc))
        {
            goto bad;
        }
    }
    proxy_connection_io_requeue(pc, rwflags_pc, es);
    proxy_connection_io_requeue(cp, rwflags_cp, es);

    return true;

bad:
    proxy_entry_mark_for_close(pc, es);
    return false;
}

/*
 * This is the main function for the port share proxy background process.
 */
static void
port_share_proxy(const struct sockaddr_in hostaddr,
                 const socket_descriptor_t sd_control,
                 const int max_initial_buf,
                 const char *journal_dir)
{
    if (send_control(sd_control, RESPONSE_INIT_SUCCEEDED) >= 0)
    {
        void *sd_control_marker = (void *)1;
        int maxevents = 256;
        struct event_set *es;
        struct event_set_return esr[64];
        struct proxy_connection *list = NULL;
        time_t last_housekeeping = 0;

        msg(D_PS_PROXY, "PORT SHARE PROXY: proxy starting");

        es = event_set_init(&maxevents, 0);
        event_ctl(es, sd_control, EVENT_READ, sd_control_marker);
        while (true)
        {
            int n_events;
            struct timeval tv;
            time_t current;

            tv.tv_sec = 10;
            tv.tv_usec = 0;
            n_events = event_wait(es, &tv, esr, SIZE(esr));
            /*dmsg (D_PS_PROXY_DEBUG, "PORT SHARE PROXY: event_wait returned %d", n_events);*/
            current = time(NULL);
            if (n_events > 0)
            {
                int i;
                for (i = 0; i < n_events; ++i)
                {
                    const struct event_set_return *e = &esr[i];
                    if (e->arg == sd_control_marker)
                    {
                        if (!control_message_from_parent(sd_control, &list, es, hostaddr, max_initial_buf, journal_dir))
                        {
                            goto done;
                        }
                    }
                    else
                    {
                        struct proxy_connection *pc = (struct proxy_connection *)e->arg;
                        if (pc->defined)
                        {
                            proxy_connection_io_dispatch(pc, e->rwflags, es);
                        }
                    }
                }
            }
            else if (n_events < 0)
            {
                dmsg(D_PS_PROXY_DEBUG, "PORT SHARE PROXY: event_wait failed");
            }
            if (current > last_housekeeping)
            {
                proxy_list_housekeeping(&list);
                last_housekeeping = current;
            }
        }

done:
        proxy_list_close(&list);
        event_free(es);
    }
    msg(M_INFO, "PORT SHARE PROXY: proxy exiting");
}

/*
 * Called from the main OpenVPN process to enable the port
 * share proxy.
 */
struct port_share *
port_share_open(const char *host,
                const char *port,
                const int max_initial_buf,
                const char *journal_dir)
{
    pid_t pid;
    socket_descriptor_t fd[2];
    struct sockaddr_in hostaddr;
    struct port_share *ps;
    int status;
    struct addrinfo *ai;

    ALLOC_OBJ_CLEAR(ps, struct port_share);
    ps->foreground_fd = -1;
    ps->background_pid = -1;

    /*
     * Get host's IP address
     */

    status = openvpn_getaddrinfo(GETADDR_RESOLVE|GETADDR_FATAL,
                                 host, port,  0, NULL, AF_INET, &ai);
    ASSERT(status==0);
    hostaddr = *((struct sockaddr_in *) ai->ai_addr);
    freeaddrinfo(ai);

    /*
     * Make a socket for foreground and background processes
     * to communicate.
     */
    if (socketpair(PF_UNIX, SOCK_DGRAM, 0, fd) == -1)
    {
        msg(M_WARN, "PORT SHARE: socketpair call failed");
        goto error;
    }

    /*
     * Fork off background proxy process.
     */
    pid = fork();

    if (pid)
    {
        int status;

        /*
         * Foreground Process
         */

        ps->background_pid = pid;

        /* close our copy of child's socket */
        openvpn_close_socket(fd[1]);

        /* don't let future subprocesses inherit child socket */
        set_cloexec(fd[0]);

        /* wait for background child process to initialize */
        status = recv_control(fd[0]);
        if (status == RESPONSE_INIT_SUCCEEDED)
        {
            /* note that this will cause possible EAGAIN when writing to
             * control socket if proxy process is backlogged */
            set_nonblock(fd[0]);

            ps->foreground_fd = fd[0];
            return ps;
        }
        else
        {
            msg(M_ERR, "PORT SHARE: unexpected init recv_control status=%d", status);
        }
    }
    else
    {
        /*
         * Background Process
         */

        /* Ignore most signals (the parent will receive them) */
        set_signals();

        /* Let msg know that we forked */
        msg_forked();

#ifdef ENABLE_MANAGEMENT
        /* Don't interact with management interface */
        management = NULL;
#endif

        /* close all parent fds except our socket back to parent */
        close_fds_except(fd[1]);

        /* no blocking on control channel back to parent */
        set_nonblock(fd[1]);

        /* execute the event loop */
        port_share_proxy(hostaddr, fd[1], max_initial_buf, journal_dir);

        openvpn_close_socket(fd[1]);

        exit(0);
        return NULL; /* NOTREACHED */
    }

error:
    port_share_close(ps);
    return NULL;
}

void
port_share_close(struct port_share *ps)
{
    if (ps)
    {
        if (ps->foreground_fd >= 0)
        {
            /* tell background process to exit */
            port_share_sendmsg(ps->foreground_fd, COMMAND_EXIT, NULL, SOCKET_UNDEFINED);

            /* wait for background process to exit */
            dmsg(D_PS_PROXY_DEBUG, "PORT SHARE: waiting for background process to exit");
            if (ps->background_pid > 0)
            {
                waitpid(ps->background_pid, NULL, 0);
            }
            dmsg(D_PS_PROXY_DEBUG, "PORT SHARE: background process exited");

            openvpn_close_socket(ps->foreground_fd);
            ps->foreground_fd = -1;
        }

        free(ps);
    }
}

void
port_share_abort(struct port_share *ps)
{
    if (ps)
    {
        /* tell background process to exit */
        if (ps->foreground_fd >= 0)
        {
            send_control(ps->foreground_fd, COMMAND_EXIT);
            openvpn_close_socket(ps->foreground_fd);
            ps->foreground_fd = -1;
        }
    }
}

/*
 * Given either the first 2 or 3 bytes of an initial client -> server
 * data payload, return true if the protocol is that of an OpenVPN
 * client attempting to connect with an OpenVPN server.
 */
bool
is_openvpn_protocol(const struct buffer *buf)
{
    const unsigned char *p = (const unsigned char *) BSTR(buf);
    const int len = BLEN(buf);
    if (len >= 3)
    {
        int plen = (p[0] << 8) | p[1];

        if (p[2] == (P_CONTROL_HARD_RESET_CLIENT_V3 << P_OPCODE_SHIFT))
        {
            /* WKc is at least 290 byte (not including metadata):
             *
             * 16 bit len + 256 bit HMAC + 2048 bit Kc = 2320 bit
             *
             * This is increased by the normal length of client handshake +
             * tls-crypt overhead (32)
             *
             * For metadata tls-crypt-v2.txt does not explicitly specify
             * an upper limit but we also have TLS_CRYPT_V2_MAX_WKC_LEN
             * as 1024 bytes. We err on the safe side with 255 extra overhead
             *
             * We don't do the 2 byte check for tls-crypt-v2 because it is very
             * unrealistic to have only 2 bytes available.
             */
            return  (plen >= 336 && plen < (1024 + 255));
        }
        else
        {
            /* For non tls-crypt2 we assume the packet length to valid between
             * 14 and 255 */
            return plen >= 14 && plen <= 255
                   && (p[2] == (P_CONTROL_HARD_RESET_CLIENT_V2 << P_OPCODE_SHIFT));
        }
    }
    else if (len >= 2)
    {
        int plen = (p[0] << 8) | p[1];
        return plen >= 14 && plen <= 255;
    }
    else
    {
        return true;
    }
}

/*
 * Called from the foreground process.  Send a message to the background process that it
 * should proxy the TCP client on sd to the host/port defined in the initial port_share_open
 * call.
 */
void
port_share_redirect(struct port_share *ps, const struct buffer *head, socket_descriptor_t sd)
{
    if (ps)
    {
        port_share_sendmsg(ps->foreground_fd, COMMAND_REDIRECT, head, sd);
    }
}

#endif /* if PORT_SHARE */
