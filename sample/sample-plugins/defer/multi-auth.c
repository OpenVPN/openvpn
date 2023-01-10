/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

/*
 * This file implements a simple OpenVPN plugin module which
 * can do either an instant authentication or a deferred auth.
 * The purpose of this plug-in is to test multiple auth plugins
 * in the same configuration file
 *
 * Plugin arguments:
 *
 *   multi-auth.so LOG_ID  DEFER_TIME  USERNAME  PASSWORD
 *
 * LOG_ID is just an ID string used to separate auth results in the log
 * DEFER_TIME is the time to defer the auth. Set to 0 to return immediately
 * USERNAME is the username for a valid authentication
 * PASSWORD is the password for a valid authentication
 *
 * The DEFER_TIME time unit is in ms.
 *
 * Sample usage:
 *
 * plugin multi-auth.so MA_1 0 foo bar  # Instant reply user:foo pass:bar
 * plugin multi-auth.so MA_2 5000 fux bax # Defer 5 sec, user:fux pass: bax
 *
 */
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "openvpn-plugin.h"

static char *MODULE = "multi-auth";

/*
 * Our context, where we keep our state.
 */

struct plugin_context {
    int test_deferred_auth;
    char *authid;
    char *test_valid_user;
    char *test_valid_pass;
};

/* local wrapping of the log function, to add more details */
static plugin_vlog_t _plugin_vlog_func = NULL;
static void
plog(const struct plugin_context *ctx, int flags, char *fmt, ...)
{
    char logid[129];

    if (ctx && ctx->authid)
    {
        snprintf(logid, 128, "%s[%s]", MODULE, ctx->authid);
    }
    else
    {
        snprintf(logid, 128, "%s", MODULE);
    }

    va_list arglist;
    va_start(arglist, fmt);
    _plugin_vlog_func(flags, logid, fmt, arglist);
    va_end(arglist);
}


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


struct plugin_per_client_context {
    int n_calls;
    bool generated_pf_file;
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
    if (v3structver < OPENVPN_PLUGIN_STRUCTVER_MIN)
    {
        fprintf(stderr, "%s: this plugin is incompatible with the running version of OpenVPN\n", MODULE);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* Save global pointers to functions exported from openvpn */
    _plugin_vlog_func = args->callbacks->plugin_vlog;

    plog(NULL, PLOG_NOTE, "FUNC: openvpn_plugin_open_v3");

    /*
     * Allocate our context
     */
    struct plugin_context *context = NULL;
    context = (struct plugin_context *) calloc(1, sizeof(struct plugin_context));
    if (!context)
    {
        goto error;
    }

    /* simple module argument parsing */
    if ((args->argv[4]) && !args->argv[5])
    {
        context->authid = strdup(args->argv[1]);
        context->test_deferred_auth = atoi_null0(args->argv[2]);
        context->test_valid_user = strdup(args->argv[3]);
        context->test_valid_pass = strdup(args->argv[4]);
    }
    else
    {
        plog(context, PLOG_ERR, "Too many arguments provided");
        goto error;
    }

    if (context->test_deferred_auth > 0)
    {
        plog(context, PLOG_NOTE, "TEST_DEFERRED_AUTH %d", context->test_deferred_auth);
    }

    /*
     * Which callbacks to intercept.
     */
    ret->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
    ret->handle = (openvpn_plugin_handle_t *) context;

    plog(context, PLOG_NOTE, "initialization succeeded");
    return OPENVPN_PLUGIN_FUNC_SUCCESS;

error:
    plog(context, PLOG_NOTE, "initialization failed");
    if (context)
    {
        free(context);
    }
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

static bool
do_auth_user_pass(struct plugin_context *context,
                  const char *username, const char *password)
{
    plog(context, PLOG_NOTE,
         "expect_user=%s, received_user=%s, expect_passw=%s, received_passw=%s",
         np(context->test_valid_user),
         np(username),
         np(context->test_valid_pass),
         np(password));

    if (context->test_valid_user && context->test_valid_pass)
    {
        if ((strcmp(context->test_valid_user, username) != 0)
            || (strcmp(context->test_valid_pass, password) != 0))
        {
            plog(context, PLOG_ERR,
                 "User/Password auth result: FAIL");
            return false;
        }
        else
        {
            plog(context, PLOG_NOTE,
                 "User/Password auth result: PASS");
            return true;
        }
    }
    return false;
}


static int
auth_user_pass_verify(struct plugin_context *context,
                      struct plugin_per_client_context *pcc,
                      const char *argv[], const char *envp[])
{
    /* get username/password from envp string array */
    const char *username = get_env("username", envp);
    const char *password = get_env("password", envp);

    if (!context->test_deferred_auth)
    {
        plog(context, PLOG_NOTE, "Direct authentication");
        return do_auth_user_pass(context, username, password) ?
               OPENVPN_PLUGIN_FUNC_SUCCESS : OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* get auth_control_file filename from envp string array*/
    const char *auth_control_file = get_env("auth_control_file", envp);
    plog(context, PLOG_NOTE, "auth_control_file=%s", auth_control_file);

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
        plog(context, PLOG_ERR|PLOG_ERRNO, "BACKGROUND: fork(2) failed");
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
    plog(context, PLOG_NOTE, "in async/deferred handler, usleep(%d)",
         context->test_deferred_auth*1000);
    usleep(context->test_deferred_auth*1000);

    /* now signal success state to openvpn */
    int fd = open(auth_control_file, O_WRONLY);
    if (fd < 0)
    {
        plog(context, PLOG_ERR|PLOG_ERRNO,
             "open('%s') failed", auth_control_file);
        exit(1);
    }

    char result[2] = "0\0";
    if (do_auth_user_pass(context, username, password))
    {
        result[0] = '1';
    }

    if (write(fd, result, 1) != 1)
    {
        plog(context, PLOG_ERR|PLOG_ERRNO, "write to '%s' failed", auth_control_file );
    }
    close(fd);

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
        case OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY:
            plog(context, PLOG_NOTE, "OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY");
            return auth_user_pass_verify(context, pcc, argv, envp);

        default:
            plog(context, PLOG_NOTE, "OPENVPN_PLUGIN_?");
            return OPENVPN_PLUGIN_FUNC_ERROR;
    }
}

OPENVPN_EXPORT void *
openvpn_plugin_client_constructor_v1(openvpn_plugin_handle_t handle)
{
    struct plugin_context *context = (struct plugin_context *) handle;
    plog(context, PLOG_NOTE, "FUNC: openvpn_plugin_client_constructor_v1");
    return calloc(1, sizeof(struct plugin_per_client_context));
}

OPENVPN_EXPORT void
openvpn_plugin_client_destructor_v1(openvpn_plugin_handle_t handle, void *per_client_context)
{
    struct plugin_context *context = (struct plugin_context *) handle;
    plog(context, PLOG_NOTE, "FUNC: openvpn_plugin_client_destructor_v1");
    free(per_client_context);
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct plugin_context *context = (struct plugin_context *) handle;
    plog(context, PLOG_NOTE, "FUNC: openvpn_plugin_close_v1");
    free(context);
}
