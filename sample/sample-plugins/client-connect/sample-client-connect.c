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
 * will log the calls made, and send back some config statements
 * when called on the CLIENT_CONNECT and CLIENT_CONNECT_V2 hooks.
 *
 * it can be asked to fail or go to async/deferred mode by setting
 * environment variables (UV_WANT_CC_FAIL, UV_WANT_CC_ASYNC,
 * UV_WANT_CC2_ASYNC) - mostly used as a testing vehicle for the
 * server side code to handle these cases
 *
 * See the README file for build instructions and env control variables.
 */

/* strdup() might need special defines to be visible in <string.h> */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "openvpn-plugin.h"

/* Pointers to functions exported from openvpn */
static plugin_log_t plugin_log = NULL;
static plugin_secure_memzero_t plugin_secure_memzero = NULL;
static plugin_base64_decode_t plugin_base64_decode = NULL;

/* module name for plugin_log() */
static char *MODULE = "sample-cc";

/*
 * Our context, where we keep our state.
 */

struct plugin_context {
    int verb;                           /* logging verbosity */
};

/* this is used for the CLIENT_CONNECT_V2 async/deferred handler
 *
 * the "CLIENT_CONNECT_V2" handler puts per-client information into
 * this, and the "CLIENT_CONNECT_DEFER_V2" handler looks at it to see
 * if it's time yet to succeed/fail
 */
struct plugin_per_client_context {
    time_t sleep_until;                 /* wakeup time (time() + sleep) */
    bool want_fail;
    bool want_disable;
    const char *client_config;
};

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

/* use v3 functions so we can use openvpn's logging and base64 etc. */
OPENVPN_EXPORT int
openvpn_plugin_open_v3(const int v3structver,
                       struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *ret)
{
    /* const char **argv = args->argv; */ /* command line arguments (unused) */
    const char **envp = args->envp;       /* environment variables */

    /* Check API compatibility -- struct version 5 or higher needed */
    if (v3structver < 5)
    {
        fprintf(stderr, "sample-client-connect: this plugin is incompatible with the running version of OpenVPN\n");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /*
     * Allocate our context
     */
    struct plugin_context *context = calloc(1, sizeof(struct plugin_context));
    if (!context)
    {
        goto error;
    }

    /*
     * Intercept just about everything...
     */
    ret->type_mask =
        OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_UP)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_DOWN)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_ROUTE_UP)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_IPCHANGE)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_TLS_VERIFY)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_CONNECT)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_CONNECT_V2)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER_V2)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_DISCONNECT)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_LEARN_ADDRESS)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_TLS_FINAL);

    /* Save global pointers to functions exported from openvpn */
    plugin_log = args->callbacks->plugin_log;
    plugin_secure_memzero = args->callbacks->plugin_secure_memzero;
    plugin_base64_decode = args->callbacks->plugin_base64_decode;

    /*
     * Get verbosity level from environment
     */
    context->verb = atoi_null0(get_env("verb", envp));

    ret->handle = (openvpn_plugin_handle_t *) context;
    plugin_log(PLOG_NOTE, MODULE, "initialization succeeded");
    return OPENVPN_PLUGIN_FUNC_SUCCESS;

error:
    free(context);
    return OPENVPN_PLUGIN_FUNC_ERROR;
}


/* there are two possible interfaces for an openvpn plugin how
 * to be called on "client connect", which primarily differ in the
 * way config options are handed back to the client instance
 * (see openvpn/multi.c, multi_client_connect_call_plugin_{v1,v2}())
 *
 * OPENVPN_PLUGIN_CLIENT_CONNECT
 *   openvpn creates a temp file and passes the name to the plugin
 *    (via argv[1] variable, argv[0] is the name of the plugin)
 *   the plugin can write config statements to that file, and openvpn
 *    reads it in like a "ccd/$cn" per-client config file
 *
 * OPENVPN_PLUGIN_CLIENT_CONNECT_V2
 *   the caller passes in a pointer to an "openvpn_plugin_string_list"
 *   (openvpn-plugin.h), which is a linked list of (name,value) pairs
 *
 *   we fill in one node with name="config" and value="our config"
 *
 *   both "l" and "l->name" and "l->value" are malloc()ed by the plugin
 *   and free()ed by the caller (openvpn_plugin_string_list_free())
 */

/* helper function to write actual "here are your options" file,
 * called from sync and sync handler
 */
int
write_cc_options_file(const char *name, const char **envp)
{
    if (!name)
    {
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }

    FILE *fp = fopen(name, "w");
    if (!fp)
    {
        plugin_log(PLOG_ERR, MODULE, "fopen('%s') failed", name);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* config to-be-sent can come from "setenv plugin_cc_config" in openvpn */
    const char *p = get_env("plugin_cc_config", envp);
    if (p)
    {
        fprintf(fp, "%s\n", p);
    }

    /* some generic config snippets so we know it worked */
    fprintf(fp, "push \"echo sample-cc plugin 1 called\"\n");

    /* if the caller wants, reject client by means of "disable" option */
    if (get_env("UV_WANT_CC_DISABLE", envp))
    {
        plugin_log(PLOG_NOTE, MODULE, "env has UV_WANT_CC_DISABLE, reject");
        fprintf(fp, "disable\n");
    }
    fclose(fp);

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int
cc_handle_deferred_v1(int seconds, const char *name, const char **envp)
{
    const char *ccd_file = get_env("client_connect_deferred_file", envp);
    if (!ccd_file)
    {
        plugin_log(PLOG_NOTE, MODULE, "env has UV_WANT_CC_ASYNC=%d, but "
                   "'client_connect_deferred_file' not set -> fail", seconds);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* the CLIENT_CONNECT (v1) API is a bit tricky to work with, because
     * completition can be signalled both by the "deferred_file" and by
     * the new ...CLIENT_CONNECT_DEFER API - which is optional.
     *
     * For OpenVPN to be able to differenciate, we must create the file
     * right away if we want to use that for signalling.
     */
    int fd = open(ccd_file, O_WRONLY);
    if (fd < 0)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "open('%s') failed", ccd_file);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    if (write(fd, "2", 1) != 1)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "write to '%s' failed", ccd_file );
        close(fd);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    close(fd);

    /* we do not want to complicate our lives with having to wait()
     * for child processes (so they are not zombiefied) *and* we MUST NOT
     * fiddle with signal handlers (= shared with openvpn main), so
     * we use double-fork() trick.
     */

    /* fork, sleep, succeed/fail according to env vars */
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
    if (p2 > 0)                 /* new parent: exit right away */
    {
        exit(0);
    }

    /* (grand-)child process
     *  - never call "return" now (would mess up openvpn)
     *  - return status is communicated by file
     *  - then exit()
     */

    /* do mighty complicated work that will really take time here... */
    plugin_log(PLOG_NOTE, MODULE, "in async/deferred handler, sleep(%d)", seconds);
    sleep(seconds);

    /* write config options to openvpn */
    int ret = write_cc_options_file(name, envp);

    /* by setting "UV_WANT_CC_FAIL" we can be triggered to fail */
    const char *p = get_env("UV_WANT_CC_FAIL", envp);
    if (p)
    {
        plugin_log(PLOG_NOTE, MODULE, "env has UV_WANT_CC_FAIL=%s -> fail", p);
        ret = OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* now signal success/failure state to openvpn */
    fd = open(ccd_file, O_WRONLY);
    if (fd < 0)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "open('%s') failed", ccd_file);
        exit(1);
    }

    plugin_log(PLOG_NOTE, MODULE, "cc_handle_deferred_v1: done, signalling %s",
               (ret == OPENVPN_PLUGIN_FUNC_SUCCESS) ? "success" : "fail" );

    if (write(fd, (ret == OPENVPN_PLUGIN_FUNC_SUCCESS) ? "1" : "0", 1) != 1)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "write to '%s' failed", ccd_file );
    }
    close(fd);

    exit(0);
}

int
openvpn_plugin_client_connect(struct plugin_context *context,
                              const char **argv,
                              const char **envp)
{
    /* log environment variables handed to us by OpenVPN, but
     * only if "setenv verb" is 3 or higher (arbitrary number)
     */
    if (context->verb>=3)
    {
        for (int i = 0; argv[i]; i++)
        {
            plugin_log(PLOG_NOTE, MODULE, "per-client argv: %s", argv[i]);
        }
        for (int i = 0; envp[i]; i++)
        {
            plugin_log(PLOG_NOTE, MODULE, "per-client env: %s", envp[i]);
        }
    }

    /* by setting "UV_WANT_CC_ASYNC" we go to async/deferred mode */
    const char *p = get_env("UV_WANT_CC_ASYNC", envp);
    if (p)
    {
        /* the return value will usually be OPENVPN_PLUGIN_FUNC_DEFERRED
         * ("I will do my job in the background, check the status file!")
         * but depending on env setup it might be "..._ERRROR"
         */
        return cc_handle_deferred_v1(atoi(p), argv[1], envp);
    }

    /* -- this is synchronous mode (openvpn waits for us) -- */

    /* by setting "UV_WANT_CC_FAIL" we can be triggered to fail */
    p = get_env("UV_WANT_CC_FAIL", envp);
    if (p)
    {
        plugin_log(PLOG_NOTE, MODULE, "env has UV_WANT_CC_FAIL=%s -> fail", p);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* does the caller want options?  give them some */
    int ret = write_cc_options_file(argv[1], envp);

    return ret;
}

int
openvpn_plugin_client_connect_v2(struct plugin_context *context,
                                 struct plugin_per_client_context *pcc,
                                 const char **envp,
                                 struct openvpn_plugin_string_list **return_list)
{
    /* by setting "UV_WANT_CC2_ASYNC" we go to async/deferred mode */
    const char *want_async = get_env("UV_WANT_CC2_ASYNC", envp);
    const char *want_fail = get_env("UV_WANT_CC2_FAIL", envp);
    const char *want_disable = get_env("UV_WANT_CC2_DISABLE", envp);

    /* config to push towards client - can be controlled by OpenVPN
     * config ("setenv plugin_cc2_config ...") - mostly useful in a
     * regression test environment to push stuff like routes which are
     * then verified by t_client ping tests
     */
    const char *client_config = get_env("plugin_cc2_config", envp);
    if (!client_config)
    {
        /* pick something meaningless which can be verified in client log */
        client_config = "push \"setenv CC2 MOOH\"\n";
    }

    if (want_async)
    {
        /* we do no really useful work here, so we just tell the
         * "CLIENT_CONNECT_DEFER_V2" handler that it should sleep
         * and then "do things" via the per-client-context
         */
        pcc->sleep_until = time(NULL) + atoi(want_async);
        pcc->want_fail = (want_fail != NULL);
        pcc->want_disable = (want_disable != NULL);
        pcc->client_config = client_config;
        plugin_log(PLOG_NOTE, MODULE, "env has UV_WANT_CC2_ASYNC=%s -> set up deferred handler", want_async);
        return OPENVPN_PLUGIN_FUNC_DEFERRED;
    }

    /* by setting "UV_WANT_CC2_FAIL" we can be triggered to fail here */
    if (want_fail)
    {
        plugin_log(PLOG_NOTE, MODULE, "env has UV_WANT_CC2_FAIL=%s -> fail", want_fail);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    struct openvpn_plugin_string_list *rl =
        calloc(1, sizeof(struct openvpn_plugin_string_list));
    if (!rl)
    {
        plugin_log(PLOG_ERR, MODULE, "malloc(return_list) failed");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    rl->name = strdup("config");
    if (want_disable)
    {
        plugin_log(PLOG_NOTE, MODULE, "env has UV_WANT_CC2_DISABLE, reject");
        rl->value = strdup("disable\n");
    }
    else
    {
        rl->value = strdup(client_config);
    }

    if (!rl->name || !rl->value)
    {
        plugin_log(PLOG_ERR, MODULE, "malloc(return_list->xx) failed");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    *return_list = rl;

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int
openvpn_plugin_client_connect_defer_v2(struct plugin_context *context,
                                       struct plugin_per_client_context *pcc,
                                       struct openvpn_plugin_string_list
                                       **return_list)
{
    time_t time_left = pcc->sleep_until - time(NULL);
    plugin_log(PLOG_NOTE, MODULE, "defer_v2: seconds left=%d",
               (int) time_left);

    /* not yet due? */
    if (time_left > 0)
    {
        return OPENVPN_PLUGIN_FUNC_DEFERRED;
    }

    /* client wants fail? */
    if (pcc->want_fail)
    {
        plugin_log(PLOG_NOTE, MODULE, "env has UV_WANT_CC2_FAIL -> fail" );
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* fill in RL according to with-disable / without-disable */

    /* TODO: unify this with non-deferred case */
    struct openvpn_plugin_string_list *rl =
        calloc(1, sizeof(struct openvpn_plugin_string_list));
    if (!rl)
    {
        plugin_log(PLOG_ERR, MODULE, "malloc(return_list) failed");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    rl->name = strdup("config");
    if (pcc->want_disable)
    {
        plugin_log(PLOG_NOTE, MODULE, "env has UV_WANT_CC2_DISABLE, reject");
        rl->value = strdup("disable\n");
    }
    else
    {
        rl->value = strdup(pcc->client_config);
    }

    if (!rl->name || !rl->value)
    {
        plugin_log(PLOG_ERR, MODULE, "malloc(return_list->xx) failed");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    *return_list = rl;

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v2(openvpn_plugin_handle_t handle,
                       const int type,
                       const char *argv[],
                       const char *envp[],
                       void *per_client_context,
                       struct openvpn_plugin_string_list **return_list)
{
    struct plugin_context *context = (struct plugin_context *) handle;
    struct plugin_per_client_context *pcc = (struct plugin_per_client_context *) per_client_context;

    /* for most functions, we just "don't do anything" but log the
     * event received (so one can follow it in the log and understand
     * the sequence of events).  CONNECT and CONNECT_V2 are handled
     */
    switch (type)
    {
        case OPENVPN_PLUGIN_UP:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_UP");
            break;

        case OPENVPN_PLUGIN_DOWN:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_DOWN");
            break;

        case OPENVPN_PLUGIN_ROUTE_UP:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_ROUTE_UP");
            break;

        case OPENVPN_PLUGIN_IPCHANGE:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_IPCHANGE");
            break;

        case OPENVPN_PLUGIN_TLS_VERIFY:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_TLS_VERIFY");
            break;

        case OPENVPN_PLUGIN_CLIENT_CONNECT:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_CLIENT_CONNECT");
            return openvpn_plugin_client_connect(context, argv, envp);

        case OPENVPN_PLUGIN_CLIENT_CONNECT_V2:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_CLIENT_CONNECT_V2");
            return openvpn_plugin_client_connect_v2(context, pcc, envp,
                                                    return_list);

        case OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER_V2:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER_V2");
            return openvpn_plugin_client_connect_defer_v2(context, pcc,
                                                          return_list);

        case OPENVPN_PLUGIN_CLIENT_DISCONNECT:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_CLIENT_DISCONNECT");
            break;

        case OPENVPN_PLUGIN_LEARN_ADDRESS:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_LEARN_ADDRESS");
            break;

        case OPENVPN_PLUGIN_TLS_FINAL:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_TLS_FINAL");
            break;

        default:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_? type=%d\n", type);
    }
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void *
openvpn_plugin_client_constructor_v1(openvpn_plugin_handle_t handle)
{
    printf("FUNC: openvpn_plugin_client_constructor_v1\n");
    return calloc(1, sizeof(struct plugin_per_client_context));
}

OPENVPN_EXPORT void
openvpn_plugin_client_destructor_v1(openvpn_plugin_handle_t handle, void *per_client_context)
{
    printf("FUNC: openvpn_plugin_client_destructor_v1\n");
    free(per_client_context);
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct plugin_context *context = (struct plugin_context *) handle;
    printf("FUNC: openvpn_plugin_close_v1\n");
    free(context);
}
