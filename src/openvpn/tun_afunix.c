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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "tun.h"
#include "fdmisc.h"
#include "run_command.h"
#include "manage.h"
#include "win32.h"
#include "wfp_block.h"
#include "argv.h"
#include "options.h"
#include "socket.h"

#ifndef WIN32
/* Windows does implement some AF_UNIX functionality but key features
 * like socketpair() and SOCK_DGRAM are missing */

#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>



static void
tun_afunix_exec_child(const char *dev_node, struct tuntap *tt, struct env_set *env)
{
    const char *msgprefix = "ERROR: failure executing process for tun:";
    struct argv argv = argv_new();

    /* since we know that dev-node starts with unix: we can just skip that
     * to get the program name */
    const char *program = dev_node + strlen("unix:");

    argv_printf(&argv, "%s", program);

    tt->afunix.childprocess = openvpn_execve_check(&argv, env, S_NOWAITPID,
                                                   msgprefix);
    if (!openvpn_waitpid_check(tt->afunix.childprocess, msgprefix, M_WARN))
    {
        tt->afunix.childprocess = 0;
    }
    argv_free(&argv);
}

void
open_tun_afunix(struct options *o,
                int mtu,
                struct tuntap *tt,
                struct env_set *orig_env)
{
    struct gc_arena gc = gc_new();

    int fds[2];
    if (!(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) == 0))
    {
        msg(M_ERR, "Cannot create socket pair for AF_UNIX socket to external "
            "program");
        return;
    }


    /* Ensure that the buffer sizes are decently sized. Otherwise macOS will
     * just have 2048 */
    struct socket_buffer_size newsizes = {65536, 65536 };
    socket_set_buffers(fds[0], &newsizes, false);
    socket_set_buffers(fds[1], &newsizes, false);

    /* Use the first file descriptor for our side and avoid passing it
     * to the child */
    tt->fd = fds[1];
    set_cloexec(tt->fd);

    /* Make a copy of the env, so we do not need to delete our custom
     * environment variables later */
    struct env_set *env = env_set_create(&gc);
    env_set_inherit(env, orig_env);

    setenv_int(env, "TUNTAP_SOCKET_FD", fds[0]);
    setenv_str(env, "TUNTAP_DEV_TYPE", dev_type_string(o->dev, o->dev_type));
    setenv_int(env, "TUNTAP_MTU", mtu);
    if (o->route_default_gateway)
    {
        setenv_str(env, "ifconfig_gateway", o->route_default_gateway);
    }
    if (o->lladdr)
    {
        setenv_str(env, "TUNTAP_LLADDR", o->lladdr);
    }

    tun_afunix_exec_child(o->dev_node, tt, env);

    close(fds[0]);

    /* tt->actual_name is passed to up and down scripts and used as the ifconfig dev name */
    tt->actual_name = string_alloc("internal:af_unix", NULL);

    gc_free(&gc);
}

void
close_tun_afunix(struct tuntap *tt)
{
    ASSERT(tt);
    if (tt->fd >= 0)
    {
        close(tt->fd);
        tt->fd = 0;
    }
    kill(tt->afunix.childprocess, SIGINT);

    free(tt->actual_name);
    free(tt);
}

ssize_t
write_tun_afunix(struct tuntap *tt, uint8_t *buf, int len)
{
    const char *msg = "ERROR: failure during write to AF_UNIX socket: ";
    if (!openvpn_waitpid_check(tt->afunix.childprocess, msg, M_WARN))
    {
        tt->afunix.childprocess = 0;
        return -ENXIO;
    }

    return write(tt->fd, buf, len);
}

ssize_t
read_tun_afunix(struct tuntap *tt, uint8_t *buf, int len)
{
    const char *msg = "ERROR: failure during read from AF_UNIX socket: ";
    if (!openvpn_waitpid_check(tt->afunix.childprocess, msg, M_WARN))
    {
        tt->afunix.childprocess = 0;
    }
    /* do an actual read on the file descriptor even in the error case since
     * we otherwise loop on this on this from select and spam the console
     * with error messages */
    return read(tt->fd, buf, len);
}
#else  /* ifndef WIN32 */
void
open_tun_afunix(const char *dev, const char *dev_type, int mtu,
                struct tuntap *tt, struct env_set env)
{
    msg(M_ERR, "AF_UNIX socket support not available on this platform");
}

void
close_tun_afunix(struct tuntap *tt)
{
    /* should never be called as open_tun_afunix always fails */
    ASSERT(0);
}

ssize_t
write_tun_afunix(struct tuntap *tt, uint8_t *buf, int len)
{
    /* should never be called as open_tun_afunix always fails */
    ASSERT(0);
}

ssize_t
read_tun_afunix(struct tuntap *tt, uint8_t *buf, int len)
{
    /* should never be called as open_tun_afunix always fails */
    ASSERT(0);
}

#endif /* ifndef WIN32 */
