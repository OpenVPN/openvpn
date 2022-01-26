/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
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
 * This file implements a simple OpenVPN plugin module which
 * will test deferred authentication and packet filtering.
 *
 * Will run on Windows or *nix.
 *
 * Sample usage:
 *
 * setenv test_deferred_auth 20
 * setenv test_packet_filter 10
 * plugin plugin/defer/simple.so
 *
 * This will enable deferred authentication to occur 20
 * seconds after the normal TLS authentication process,
 * and will cause a packet filter file to be generated 10
 * seconds after the initial TLS negotiation, using
 * {common-name}.pf as the source.
 *
 * Sample packet filter configuration:
 *
 * [CLIENTS DROP]
 * +otherclient
 * [SUBNETS DROP]
 * +10.0.0.0/8
 * -10.10.0.8
 * [END]
 *
 * See the README file for build instructions.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "openvpn-plugin.h"

/* Pointers to functions exported from openvpn */
static plugin_log_t plugin_log = NULL;

/*
 * Constants indicating minimum API and struct versions by the functions
 * in this plugin.  Consult openvpn-plugin.h, look for:
 * OPENVPN_PLUGIN_VERSION and OPENVPN_PLUGINv3_STRUCTVER
 *
 * Strictly speaking, this sample code only requires plugin_log, a feature
 * of structver version 1.  However, '1' lines up with ancient versions
 * of openvpn that are past end-of-support.  As such, we are requiring
 * structver '5' here to indicate a desire for modern openvpn, rather
 * than a need for any particular feature found in structver beyond '1'.
 */
#define OPENVPN_PLUGIN_VERSION_MIN 3
#define OPENVPN_PLUGIN_STRUCTVER_MIN 5

/*
 * Our context, where we keep our state.
 */

struct plugin_context {
    int test_deferred_auth;
    int test_packet_filter;
};

struct plugin_per_client_context {
    int n_calls;
    bool generated_pf_file;
};

/* module name for plugin_log() */
static char *MODULE = "defer/simple";

/*
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 */
static const char *
get_env(const char *name, const char *envp[])
{
    if (envp)
    {
        int i;
        const int namelen = strlen(name);
        for (i = 0; envp[i]; ++i)
        {
            if (!strncmp(envp[i], name, namelen))
            {
                const char *cp = envp[i] + namelen;
                if (*cp == '=')
                {
                    return cp + 1;
                }
            }
        }
    }
    return NULL;
}

/* used for safe printf of possible NULL strings */
static const char *
np(const char *str)
{
    if (str)
    {
        return str;
    }
    else
    {
        return "[NULL]";
    }
}

static int
atoi_null0(const char *str)
{
    if (str)
    {
        return atoi(str);
    }
    else
    {
        return 0;
    }
}

/* Require a minimum OpenVPN Plugin API */
OPENVPN_EXPORT int
openvpn_plugin_min_version_required_v1()
{
    return OPENVPN_PLUGIN_VERSION_MIN;
}

/* use v3 functions so we can use openvpn's logging and base64 etc. */
OPENVPN_EXPORT int
openvpn_plugin_open_v3(const int v3structver,
                       struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *ret)
{
    const char **envp = args->envp;       /* environment variables */
    struct plugin_context *context;

    if (v3structver < OPENVPN_PLUGIN_STRUCTVER_MIN)
    {
        fprintf(stderr, "%s: this plugin is incompatible with the running version of OpenVPN\n", MODULE);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* Save global pointers to functions exported from openvpn */
    plugin_log = args->callbacks->plugin_log;

    plugin_log(PLOG_NOTE, MODULE, "FUNC: openvpn_plugin_open_v3");

    /*
     * Allocate our context
     */
    context = (struct plugin_context *) calloc(1, sizeof(struct plugin_context));
    if (!context)
    {
        goto error;
    }

    context->test_deferred_auth = atoi_null0(get_env("test_deferred_auth", envp));
    plugin_log(PLOG_NOTE, MODULE, "TEST_DEFERRED_AUTH %d", context->test_deferred_auth);

    context->test_packet_filter = atoi_null0(get_env("test_packet_filter", envp));
    plugin_log(PLOG_NOTE, MODULE, "TEST_PACKET_FILTER %d", context->test_packet_filter);

    /*
     * Which callbacks to intercept.
     */
    ret->type_mask =
        OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_UP)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_DOWN)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_ROUTE_UP)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_IPCHANGE)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_TLS_VERIFY)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_CONNECT_V2)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_DISCONNECT)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_LEARN_ADDRESS)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_TLS_FINAL);

    /* ENABLE_PF should only be called if we're actually willing to do PF */
    if (context->test_packet_filter)
    {
        ret->type_mask |= OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_ENABLE_PF);
    }

    ret->handle = (openvpn_plugin_handle_t *) context;
    plugin_log(PLOG_NOTE, MODULE, "initialization succeeded");
    return OPENVPN_PLUGIN_FUNC_SUCCESS;

error:
    if (context)
    {
        free(context);
    }
    plugin_log(PLOG_NOTE, MODULE, "initialization failed");
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

static int
auth_user_pass_verify(struct plugin_context *context,
                      struct plugin_per_client_context *pcc,
                      const char *argv[], const char *envp[])
{
    if (!context->test_deferred_auth)
    {
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }

    /* get username/password from envp string array */
    const char *username = get_env("username", envp);
    const char *password = get_env("password", envp);

    /* get auth_control_file filename from envp string array*/
    const char *auth_control_file = get_env("auth_control_file", envp);

    plugin_log(PLOG_NOTE, MODULE, "DEFER u='%s' p='%s' acf='%s'",
               np(username),
               np(password),
               np(auth_control_file));

    /* Authenticate asynchronously in n seconds */
    if (!auth_control_file)
    {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* we do not want to complicate our lives with having to wait()
     * for child processes (so they are not zombiefied) *and* we MUST NOT
     * fiddle with signal handlers (= shared with openvpn main), so
     * we use double-fork() trick.
     */

    /* fork, sleep, succeed (no "real" auth done = always succeed) */
    pid_t p1 = fork();
    if (p1 < 0)                 /* Fork failed */
    {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    if (p1 > 0)                 /* parent process */
    {
        waitpid(p1, NULL, 0);
        return OPENVPN_PLUGIN_FUNC_DEFERRED;
    }

    /* first gen child process, fork() again and exit() right away */
    pid_t p2 = fork();
    if (p2 < 0)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "BACKGROUND: fork(2) failed");
        exit(1);
    }

    if (p2 != 0)                            /* new parent: exit right away */
    {
        exit(0);
    }

    /* (grand-)child process
     *  - never call "return" now (would mess up openvpn)
     *  - return status is communicated by file
     *  - then exit()
     */

    /* do mighty complicated work that will really take time here... */
    plugin_log(PLOG_NOTE, MODULE, "in async/deferred handler, sleep(%d)", context->test_deferred_auth);
    sleep(context->test_deferred_auth);

    /* now signal success state to openvpn */
    int fd = open(auth_control_file, O_WRONLY);
    if (fd < 0)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "open('%s') failed", auth_control_file);
        exit(1);
    }

    plugin_log(PLOG_NOTE, MODULE, "auth_user_pass_verify: done" );

    if (write(fd, "1", 1) != 1)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "write to '%s' failed", auth_control_file );
    }
    close(fd);

    exit(0);
}

static int
tls_final(struct plugin_context *context, struct plugin_per_client_context *pcc, const char *argv[], const char *envp[])
{
    if (!context->test_packet_filter)   /* no PF testing, nothing to do */
    {
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }

    if (pcc->generated_pf_file)         /* we already have created a file */
    {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    const char *pff = get_env("pf_file", envp);
    const char *cn = get_env("username", envp);
    if (!pff || !cn)                    /* required vars missing */
    {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    pcc->generated_pf_file = true;

    /* the PF API is, basically
     *  - OpenVPN sends a filename (pf_file) to the plugin
     *  - OpenVPN main loop will check every second if that file shows up
     *  - when it does, it will be read & used for the pf config
     * the pre-created file needs to be removed in ...ENABLE_PF
     * to make deferred PF setup work
     *
     * the regular PF hook does not know the client username or CN, so
     * this is deferred to the TLS_FINAL hook which knows these things
     */

    /* do the double fork dance (see above for more verbose comments)
     */
    pid_t p1 = fork();
    if (p1 < 0)                 /* Fork failed */
    {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    if (p1 > 0)                 /* parent process */
    {
        waitpid(p1, NULL, 0);
        return OPENVPN_PLUGIN_FUNC_SUCCESS;     /* no _DEFERRED here! */
    }

    /* first gen child process, fork() again and exit() right away */
    pid_t p2 = fork();
    if (p2 < 0)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "BACKGROUND: fork(2) failed");
        exit(1);
    }

    if (p2 != 0)                            /* new parent: exit right away */
    {
        exit(0);
    }

    /* (grand-)child process
     *  - never call "return" now (would mess up openvpn)
     *  - return status is communicated by file
     *  - then exit()
     */

    /* at this point, the plugin can take its time, because OpenVPN will
     * no longer block waiting for the call to finish
     *
     * in this example, we build a PF file by copying over a file
     * named "<username>.pf" to the OpenVPN-provided pf file name
     *
     * a real example could do a LDAP lookup, a REST call, ...
     */
    plugin_log(PLOG_NOTE, MODULE, "in async/deferred tls_final handler, sleep(%d)", context->test_packet_filter);
    sleep(context->test_packet_filter);

    char buf[256];
    snprintf(buf, sizeof(buf), "%s.pf", cn );

    /* there is a small race condition here - OpenVPN could detect our
     * file while we have only written half of it.  So "perfect" code
     * needs to create this with a temp file name, and then rename() it
     * after it has been written.  But I am lazy.
     */

    int w_fd = open( pff, O_WRONLY|O_CREAT, 0600 );
    if (w_fd < 0)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "can't write to '%s'", pff);
        exit(0);
    }

    int r_fd = open( buf, O_RDONLY );
    if (r_fd < 0)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "can't read '%s', creating empty pf file", buf);
        close(w_fd);
        exit(0);
    }

    char data[1024];

    int r;
    do
    {
        r = read(r_fd, data, sizeof(data));
        if (r < 0)
        {
            plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "error reading '%s'", buf);
            close(r_fd);
            close(w_fd);
            exit(0);
        }
        int w = write(w_fd, data, r);
        if (w < 0 || w != r)
        {
            plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "error writing %d bytes to '%s'", r, pff);
            close(r_fd);
            close(w_fd);
            exit(0);
        }
    }
    while(r > 0);

    plugin_log(PLOG_NOTE, MODULE, "copied PF config from '%s' to '%s', job done", buf, pff);
    exit(0);
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3(const int v3structver,
                       struct openvpn_plugin_args_func_in const *args,
                       struct openvpn_plugin_args_func_return *ret)
{
    if (v3structver < OPENVPN_PLUGIN_STRUCTVER_MIN)
    {
        fprintf(stderr, "%s: this plugin is incompatible with the running version of OpenVPN\n", MODULE);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    const char **argv = args->argv;
    const char **envp = args->envp;
    struct plugin_context *context = (struct plugin_context *) args->handle;
    struct plugin_per_client_context *pcc = (struct plugin_per_client_context *) args->per_client_context;
    switch (args->type)
    {
        case OPENVPN_PLUGIN_UP:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_UP");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;

        case OPENVPN_PLUGIN_DOWN:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_DOWN");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;

        case OPENVPN_PLUGIN_ROUTE_UP:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_ROUTE_UP");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;

        case OPENVPN_PLUGIN_IPCHANGE:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_IPCHANGE");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;

        case OPENVPN_PLUGIN_TLS_VERIFY:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_TLS_VERIFY");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;

        case OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY");
            return auth_user_pass_verify(context, pcc, argv, envp);

        case OPENVPN_PLUGIN_CLIENT_CONNECT_V2:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_CLIENT_CONNECT_V2");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;

        case OPENVPN_PLUGIN_CLIENT_DISCONNECT:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_CLIENT_DISCONNECT");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;

        case OPENVPN_PLUGIN_LEARN_ADDRESS:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_LEARN_ADDRESS");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;

        case OPENVPN_PLUGIN_TLS_FINAL:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_TLS_FINAL");
            return tls_final(context, pcc, argv, envp);

        case OPENVPN_PLUGIN_ENABLE_PF:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_ENABLE_PF");

            /* OpenVPN pre-creates the file, which gets in the way of
             * deferred pf setup - so remove it here, and re-create
             * it in the background handler (in tls_final()) when ready
             */
            const char *pff = get_env("pf_file", envp);
            if (pff)
            {
                (void) unlink(pff);
            }
            return OPENVPN_PLUGIN_FUNC_SUCCESS;           /* must succeed */

        default:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_?");
            return OPENVPN_PLUGIN_FUNC_ERROR;
    }
}

OPENVPN_EXPORT void *
openvpn_plugin_client_constructor_v1(openvpn_plugin_handle_t handle)
{
    plugin_log(PLOG_NOTE, MODULE, "FUNC: openvpn_plugin_client_constructor_v1");
    return calloc(1, sizeof(struct plugin_per_client_context));
}

OPENVPN_EXPORT void
openvpn_plugin_client_destructor_v1(openvpn_plugin_handle_t handle, void *per_client_context)
{
    plugin_log(PLOG_NOTE, MODULE, "FUNC: openvpn_plugin_client_destructor_v1");
    free(per_client_context);
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct plugin_context *context = (struct plugin_context *) handle;
    plugin_log(PLOG_NOTE, MODULE, "FUNC: openvpn_plugin_close_v1");
    free(context);
}
