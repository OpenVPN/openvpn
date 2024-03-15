/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2016-2024 Selva Nair <selva.nair@gmail.com>
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
 * OpenVPN plugin module to do PAM authentication using a split
 * privilege model.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <security/pam_appl.h>

#ifdef USE_PAM_DLOPEN
#include "pamdl.h"
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <limits.h>
#include "utils.h"
#include <arpa/inet.h>
#include <openvpn-plugin.h>

#define DEBUG(verb) ((verb) >= 4)

/* Command codes for foreground -> background communication */
#define COMMAND_VERIFY 0
#define COMMAND_EXIT   1

/* Response codes for background -> foreground communication */
#define RESPONSE_INIT_SUCCEEDED   10
#define RESPONSE_INIT_FAILED      11
#define RESPONSE_VERIFY_SUCCEEDED 12
#define RESPONSE_VERIFY_FAILED    13
#define RESPONSE_DEFER            14

/* Pointers to functions exported from openvpn */
static plugin_log_t plugin_log = NULL;
static plugin_secure_memzero_t plugin_secure_memzero = NULL;
static plugin_base64_decode_t plugin_base64_decode = NULL;

/* module name for plugin_log() */
static char *MODULE = "AUTH-PAM";

/*
 * Plugin state, used by foreground
 */
struct auth_pam_context
{
    /* Foreground's socket to background process */
    int foreground_fd;

    /* Process ID of background process */
    pid_t background_pid;

    /* Verbosity level of OpenVPN */
    int verb;
};

/*
 * Name/Value pairs for conversation function.
 * Special Values:
 *
 *  "USERNAME" -- substitute client-supplied username
 *  "PASSWORD" -- substitute client-specified password
 *  "COMMONNAME" -- substitute client certificate common name
 *  "OTP" -- substitute static challenge response if available
 */

#define N_NAME_VALUE 16

struct name_value {
    const char *name;
    const char *value;
};

struct name_value_list {
    int len;
    struct name_value data[N_NAME_VALUE];
};

/*
 * Used to pass the username/password
 * to the PAM conversation function.
 */
struct user_pass {
    int verb;

    char username[128];
    char password[128];
    char common_name[128];
    char response[128];
    char remote[INET6_ADDRSTRLEN];

    const struct name_value_list *name_value_list;
};

/* Background process function */
static void pam_server(int fd, const char *service, int verb, const struct name_value_list *name_value_list);


/*
 * Socket read/write functions.
 */

static int
recv_control(int fd)
{
    unsigned char c;
    const ssize_t size = read(fd, &c, sizeof(c));
    if (size == sizeof(c))
    {
        return c;
    }
    else
    {
        /*fprintf (stderr, "AUTH-PAM: DEBUG recv_control.read=%d\n", (int)size);*/
        return -1;
    }
}

static int
send_control(int fd, int code)
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
recv_string(int fd, char *buffer, int len)
{
    if (len > 0)
    {
        ssize_t size;
        memset(buffer, 0, len);
        size = read(fd, buffer, len);
        buffer[len-1] = 0;
        if (size >= 1)
        {
            return (int)size;
        }
    }
    return -1;
}

static int
send_string(int fd, const char *string)
{
    const int len = strlen(string) + 1;
    const ssize_t size = write(fd, string, len);
    if (size == len)
    {
        return (int) size;
    }
    else
    {
        return -1;
    }
}

#ifdef DO_DAEMONIZE

/*
 * Daemonize if "daemon" env var is true.
 * Preserve stderr across daemonization if
 * "daemon_log_redirect" env var is true.
 */
static void
daemonize(const char *envp[])
{
    const char *daemon_string = get_env("daemon", envp);
    if (daemon_string && daemon_string[0] == '1')
    {
        const char *log_redirect = get_env("daemon_log_redirect", envp);
        int fd = -1;
        if (log_redirect && log_redirect[0] == '1')
        {
            fd = dup(2);
        }
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
        if (daemon(0, 0) < 0)
        {
            plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "daemonization failed");
        }
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic pop
#endif
        else if (fd >= 3)
        {
            dup2(fd, 2);
            close(fd);
        }
    }
}

#endif /* ifdef DO_DAEMONIZE */

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
    int i;
    closelog();
    for (i = 3; i <= 100; ++i)
    {
        if (i != keep)
        {
            close(i);
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
 * Return 1 if query matches match.
 */
static int
name_value_match(const char *query, const char *match)
{
    while (!isalnum(*query))
    {
        if (*query == '\0')
        {
            return 0;
        }
        ++query;
    }
    return strncasecmp(match, query, strlen(match)) == 0;
}

/*
 * Split and decode up->password in the form SCRV1:base64_pass:base64_response
 * into pass and response and save in up->password and up->response.
 * If the password is not in the expected format, input is not changed.
 */
static void
split_scrv1_password(struct user_pass *up)
{
    const int skip = strlen("SCRV1:");
    if (strncmp(up->password, "SCRV1:", skip) != 0)
    {
        return;
    }

    char *tmp = strdup(up->password);
    if (!tmp)
    {
        plugin_log(PLOG_ERR, MODULE, "out of memory parsing static challenge password");
        goto out;
    }

    char *pass = tmp + skip;
    char *resp = strchr(pass, ':');
    if (!resp) /* string not in SCRV1:xx:yy format */
    {
        goto out;
    }
    *resp++ = '\0';

    int n = plugin_base64_decode(pass, up->password, sizeof(up->password)-1);
    if (n >= 0)
    {
        up->password[n] = '\0';
        n = plugin_base64_decode(resp, up->response, sizeof(up->response)-1);
        if (n >= 0)
        {
            up->response[n] = '\0';
            if (DEBUG(up->verb))
            {
                plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: parsed static challenge password");
            }
            goto out;
        }
    }

    /* decode error: reinstate original value of up->password and return */
    plugin_secure_memzero(up->password, sizeof(up->password));
    plugin_secure_memzero(up->response, sizeof(up->response));
    strcpy(up->password, tmp); /* tmp is guaranteed to fit in up->password */

    plugin_log(PLOG_ERR, MODULE, "base64 decode error while parsing static challenge password");

out:
    if (tmp)
    {
        plugin_secure_memzero(tmp, strlen(tmp));
        free(tmp);
    }
}

OPENVPN_EXPORT int
openvpn_plugin_open_v3(const int v3structver,
                       struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *ret)
{
    pid_t pid;
    int fd[2];

    struct auth_pam_context *context;
    struct name_value_list name_value_list;

    const int base_parms = 2;

    const char **argv = args->argv;
    const char **envp = args->envp;

    /* Check API compatibility -- struct version 5 or higher needed */
    if (v3structver < 5)
    {
        fprintf(stderr, "AUTH-PAM: This plugin is incompatible with the running version of OpenVPN\n");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /*
     * Allocate our context
     */
    context = (struct auth_pam_context *) calloc(1, sizeof(struct auth_pam_context));
    if (!context)
    {
        goto error;
    }
    context->foreground_fd = -1;

    /*
     * Intercept the --auth-user-pass-verify callback.
     */
    ret->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

    /* Save global pointers to functions exported from openvpn */
    plugin_log = args->callbacks->plugin_log;
    plugin_secure_memzero = args->callbacks->plugin_secure_memzero;
    plugin_base64_decode = args->callbacks->plugin_base64_decode;

    /*
     * Make sure we have two string arguments: the first is the .so name,
     * the second is the PAM service type.
     */
    if (string_array_len(argv) < base_parms)
    {
        plugin_log(PLOG_ERR, MODULE, "need PAM service parameter");
        goto error;
    }

    /*
     * See if we have optional name/value pairs to match against
     * PAM module queried fields in the conversation function.
     */
    name_value_list.len = 0;
    if (string_array_len(argv) > base_parms)
    {
        const int nv_len = string_array_len(argv) - base_parms;
        int i;

        if ((nv_len & 1) == 1 || (nv_len / 2) > N_NAME_VALUE)
        {
            plugin_log(PLOG_ERR, MODULE, "bad name/value list length");
            goto error;
        }

        name_value_list.len = nv_len / 2;
        for (i = 0; i < name_value_list.len; ++i)
        {
            const int base = base_parms + i * 2;
            name_value_list.data[i].name = argv[base];
            name_value_list.data[i].value = argv[base+1];
        }
    }

    /*
     * Get verbosity level from environment
     */
    {
        const char *verb_string = get_env("verb", envp);
        if (verb_string)
        {
            context->verb = atoi(verb_string);
        }
    }

    /*
     * Make a socket for foreground and background processes
     * to communicate.
     */
    if (socketpair(PF_UNIX, SOCK_DGRAM, 0, fd) == -1)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "socketpair call failed");
        goto error;
    }

    /*
     * Fork off the privileged process.  It will remain privileged
     * even after the foreground process drops its privileges.
     */
    pid = fork();

    if (pid)
    {
        int status;

        /*
         * Foreground Process
         */

        context->background_pid = pid;

        /* close our copy of child's socket */
        close(fd[1]);

        /* don't let future subprocesses inherit child socket */
        if (fcntl(fd[0], F_SETFD, FD_CLOEXEC) < 0)
        {
            plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "Set FD_CLOEXEC flag on socket file descriptor failed");
        }

        /* wait for background child process to initialize */
        status = recv_control(fd[0]);
        if (status == RESPONSE_INIT_SUCCEEDED)
        {
            context->foreground_fd = fd[0];
            ret->handle = (openvpn_plugin_handle_t *) context;
            plugin_log( PLOG_NOTE, MODULE, "initialization succeeded (fg)" );
            return OPENVPN_PLUGIN_FUNC_SUCCESS;
        }
    }
    else
    {
        /*
         * Background Process
         */

        /* close all parent fds except our socket back to parent */
        close_fds_except(fd[1]);

        /* Ignore most signals (the parent will receive them) */
        set_signals();

#ifdef DO_DAEMONIZE
        /* Daemonize if --daemon option is set. */
        daemonize(envp);
#endif

        /* execute the event loop */
        pam_server(fd[1], argv[1], context->verb, &name_value_list);

        close(fd[1]);

        exit(0);
        return 0; /* NOTREACHED */
    }

error:
    free(context);
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v1(openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[])
{
    struct auth_pam_context *context = (struct auth_pam_context *) handle;

    if (type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY && context->foreground_fd >= 0)
    {
        /* get username/password from envp string array */
        const char *username = get_env("username", envp);
        const char *password = get_env("password", envp);
        const char *common_name = get_env("common_name", envp) ? get_env("common_name", envp) : "";
        const char *remote = get_env("untrusted_ip6", envp);

        if (remote == NULL)
        {
            remote = get_env("untrusted_ip", envp);
        }

        if (remote == NULL)
        {
            remote = "";
        }

        /* should we do deferred auth?
         *  yes, if there is "auth_control_file" and "deferred_auth_pam" env
         */
        const char *auth_control_file = get_env("auth_control_file", envp);
        const char *deferred_auth_pam = get_env("deferred_auth_pam", envp);
        if (auth_control_file != NULL && deferred_auth_pam != NULL)
        {
            if (DEBUG(context->verb))
            {
                plugin_log(PLOG_NOTE, MODULE, "do deferred auth '%s'",
                           auth_control_file);
            }
        }
        else
        {
            auth_control_file = "";
        }

        if (username && strlen(username) > 0 && password)
        {
            if (send_control(context->foreground_fd, COMMAND_VERIFY) == -1
                || send_string(context->foreground_fd, username) == -1
                || send_string(context->foreground_fd, password) == -1
                || send_string(context->foreground_fd, common_name) == -1
                || send_string(context->foreground_fd, auth_control_file) == -1
                || send_string(context->foreground_fd, remote) == -1)
            {
                plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "Error sending auth info to background process");
            }
            else
            {
                const int status = recv_control(context->foreground_fd);
                if (status == RESPONSE_VERIFY_SUCCEEDED)
                {
                    return OPENVPN_PLUGIN_FUNC_SUCCESS;
                }
                if (status == RESPONSE_DEFER)
                {
                    if (DEBUG(context->verb))
                    {
                        plugin_log(PLOG_NOTE, MODULE, "deferred authentication");
                    }
                    return OPENVPN_PLUGIN_FUNC_DEFERRED;
                }
                if (status == -1)
                {
                    plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "Error receiving auth confirmation from background process");
                }
            }
        }
    }
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct auth_pam_context *context = (struct auth_pam_context *) handle;

    if (DEBUG(context->verb))
    {
        plugin_log(PLOG_NOTE, MODULE, "close");
    }

    if (context->foreground_fd >= 0)
    {
        /* tell background process to exit */
        if (send_control(context->foreground_fd, COMMAND_EXIT) == -1)
        {
            plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "Error signaling background process to exit");
        }

        /* wait for background process to exit */
        if (context->background_pid > 0)
        {
            waitpid(context->background_pid, NULL, 0);
        }

        close(context->foreground_fd);
        context->foreground_fd = -1;
    }

    free(context);
}

OPENVPN_EXPORT void
openvpn_plugin_abort_v1(openvpn_plugin_handle_t handle)
{
    struct auth_pam_context *context = (struct auth_pam_context *) handle;

    /* tell background process to exit */
    if (context && context->foreground_fd >= 0)
    {
        send_control(context->foreground_fd, COMMAND_EXIT);
        close(context->foreground_fd);
        context->foreground_fd = -1;
    }
}

/*
 * PAM conversation function
 */
static int
my_conv(int n, const struct pam_message **msg_array,
        struct pam_response **response_array, void *appdata_ptr)
{
    const struct user_pass *up = ( const struct user_pass *) appdata_ptr;
    struct pam_response *aresp;
    int i;
    int ret = PAM_SUCCESS;

    *response_array = NULL;

    if (n <= 0 || n > PAM_MAX_NUM_MSG)
    {
        return (PAM_CONV_ERR);
    }
    if ((aresp = calloc(n, sizeof *aresp)) == NULL)
    {
        return (PAM_BUF_ERR);
    }

    /* loop through each PAM-module query */
    for (i = 0; i < n; ++i)
    {
        const struct pam_message *msg = msg_array[i];
        aresp[i].resp_retcode = 0;
        aresp[i].resp = NULL;

        if (DEBUG(up->verb))
        {
            plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: my_conv[%d] query='%s' style=%d",
                       i,
                       msg->msg ? msg->msg : "NULL",
                       msg->msg_style);
        }

        if (up->name_value_list && up->name_value_list->len > 0)
        {
            /* use name/value list match method */
            const struct name_value_list *list = up->name_value_list;
            int j;

            /* loop through name/value pairs */
            for (j = 0; j < list->len; ++j)
            {
                const char *match_name = list->data[j].name;
                const char *match_value = list->data[j].value;

                if (name_value_match(msg->msg, match_name))
                {
                    /* found name/value match */
                    aresp[i].resp = NULL;

                    if (DEBUG(up->verb))
                    {
                        plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: name match found, query/match-string ['%s', '%s'] = '%s'",
                                   msg->msg,
                                   match_name,
                                   match_value);
                    }

                    if (strstr(match_value, "USERNAME"))
                    {
                        aresp[i].resp = searchandreplace(match_value, "USERNAME", up->username);
                    }
                    else if (strstr(match_value, "PASSWORD"))
                    {
                        aresp[i].resp = searchandreplace(match_value, "PASSWORD", up->password);
                    }
                    else if (strstr(match_value, "COMMONNAME"))
                    {
                        aresp[i].resp = searchandreplace(match_value, "COMMONNAME", up->common_name);
                    }
                    else if (strstr(match_value, "OTP"))
                    {
                        aresp[i].resp = searchandreplace(match_value, "OTP", up->response);
                    }
                    else
                    {
                        aresp[i].resp = strdup(match_value);
                    }

                    if (aresp[i].resp == NULL)
                    {
                        ret = PAM_CONV_ERR;
                    }
                    break;
                }
            }

            if (j == list->len)
            {
                ret = PAM_CONV_ERR;
            }
        }
        else
        {
            /* use PAM_PROMPT_ECHO_x hints */
            switch (msg->msg_style)
            {
                case PAM_PROMPT_ECHO_OFF:
                    aresp[i].resp = strdup(up->password);
                    if (aresp[i].resp == NULL)
                    {
                        ret = PAM_CONV_ERR;
                    }
                    break;

                case PAM_PROMPT_ECHO_ON:
                    aresp[i].resp = strdup(up->username);
                    if (aresp[i].resp == NULL)
                    {
                        ret = PAM_CONV_ERR;
                    }
                    break;

                case PAM_ERROR_MSG:
                case PAM_TEXT_INFO:
                    break;

                default:
                    ret = PAM_CONV_ERR;
                    break;
            }
        }
    }

    if (ret == PAM_SUCCESS)
    {
        *response_array = aresp;
    }
    else
    {
        free(aresp);
    }

    return ret;
}

/*
 * Return 1 if authenticated and 0 if failed.
 * Called once for every username/password
 * to be authenticated.
 */
static int
pam_auth(const char *service, const struct user_pass *up)
{
    struct pam_conv conv;
    pam_handle_t *pamh = NULL;
    int status = PAM_SUCCESS;
    int ret = 0;
    const int name_value_list_provided = (up->name_value_list && up->name_value_list->len > 0);

    /* Initialize PAM */
    conv.conv = my_conv;
    conv.appdata_ptr = (void *)up;
    status = pam_start(service, name_value_list_provided ? NULL : up->username, &conv, &pamh);
    if (status == PAM_SUCCESS)
    {
        /* Set PAM_RHOST environment variable */
        if (*(up->remote))
        {
            status = pam_set_item(pamh, PAM_RHOST, up->remote);
        }
        /* Call PAM to verify username/password */
        if (status == PAM_SUCCESS)
        {
            status = pam_authenticate(pamh, 0);
        }
        if (status == PAM_SUCCESS)
        {
            status = pam_acct_mgmt(pamh, 0);
        }
        if (status == PAM_SUCCESS)
        {
            ret = 1;
        }

        /* Output error message if failed */
        if (!ret)
        {
            plugin_log(PLOG_ERR, MODULE, "BACKGROUND: user '%s' failed to authenticate: %s",
                       up->username,
                       pam_strerror(pamh, status));
        }

        /* Close PAM */
        pam_end(pamh, status);
    }

    return ret;
}

/*
 * deferred auth handler
 *   - fork() (twice, to avoid the need for async wait / SIGCHLD handling)
 *   - query PAM stack via pam_auth()
 *   - send response back to OpenVPN via "ac_file_name"
 *
 * parent process returns "0" for "fork() and wait() succeeded",
 *                        "-1" for "something went wrong, abort program"
 */

static void
do_deferred_pam_auth(int fd, const char *ac_file_name,
                     const char *service, const struct user_pass *up)
{
    if (send_control(fd, RESPONSE_DEFER) == -1)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "BACKGROUND: write error on response socket [4]");
        return;
    }

    /* double forking so we do not need to wait() for async auth kids */
    pid_t p1 = fork();

    if (p1 < 0)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "BACKGROUND: fork(1) failed");
        return;
    }
    if (p1 != 0)                           /* parent */
    {
        waitpid(p1, NULL, 0);
        return;                            /* parent's job succeeded */
    }

    /* child */
    close(fd);                              /* socketpair no longer needed */

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

    /* grandchild */
    plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: deferred auth for '%s', pid=%d",
               up->username, (int) getpid() );

    /* the rest is very simple: do PAM, write status byte to file, done */
    int ac_fd = open( ac_file_name, O_WRONLY );
    if (ac_fd < 0)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "cannot open '%s' for writing",
                   ac_file_name );
        exit(1);
    }
    int pam_success = pam_auth(service, up);

    if (write( ac_fd, pam_success ? "1" : "0", 1 ) != 1)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "cannot write to '%s'",
                   ac_file_name );
    }
    close(ac_fd);
    plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: %s: deferred auth: PAM %s",
               up->username, pam_success ? "succeeded" : "rejected" );
    exit(0);
}

/*
 * Background process -- runs with privilege.
 */
static void
pam_server(int fd, const char *service, int verb, const struct name_value_list *name_value_list)
{
    struct user_pass up;
    char ac_file_name[PATH_MAX];
    int command;
#ifdef USE_PAM_DLOPEN
    static const char pam_so[] = "libpam.so";
#endif

    /*
     * Do initialization
     */
    if (DEBUG(verb))
    {
        plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: INIT service='%s'", service);
    }

#ifdef USE_PAM_DLOPEN
    /*
     * Load PAM shared object
     */
    if (!dlopen_pam(pam_so))
    {
        plugin_log(PLOG_ERR, MODULE, "BACKGROUND: could not load PAM lib %s: %s", pam_so, dlerror());
        send_control(fd, RESPONSE_INIT_FAILED);
        goto done;
    }
#endif

    /*
     * Tell foreground that we initialized successfully
     */
    if (send_control(fd, RESPONSE_INIT_SUCCEEDED) == -1)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "BACKGROUND: write error on response socket [1]");
        goto done;
    }

    plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: initialization succeeded");

    /*
     * Event loop
     */
    while (1)
    {
        memset(&up, 0, sizeof(up));
        up.verb = verb;
        up.name_value_list = name_value_list;

        /* get a command from foreground process */
        command = recv_control(fd);

        if (DEBUG(verb))
        {
            plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: received command code: %d", command);
        }

        switch (command)
        {
            case COMMAND_VERIFY:
                if (recv_string(fd, up.username, sizeof(up.username)) == -1
                    || recv_string(fd, up.password, sizeof(up.password)) == -1
                    || recv_string(fd, up.common_name, sizeof(up.common_name)) == -1
                    || recv_string(fd, ac_file_name, sizeof(ac_file_name)) == -1
                    || recv_string(fd, up.remote, sizeof(up.remote)) == -1)
                {
                    plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "BACKGROUND: read error on command channel: code=%d, exiting",
                               command);
                    goto done;
                }

                if (DEBUG(verb))
                {
#if 0
                    plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: USER/PASS: %s/%s",
                               up.username, up.password);
#else
                    plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: USER: %s", up.username);
                    plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: REMOTE: %s", up.remote);
#endif
                }

                /* If password is of the form SCRV1:base64:base64 split it up */
                split_scrv1_password(&up);

                /* client wants deferred auth
                 */
                if (strlen(ac_file_name) > 0)
                {
                    do_deferred_pam_auth(fd, ac_file_name, service, &up);
                    break;
                }


                /* non-deferred auth: wait for pam result and send
                 * result back via control socketpair
                 */
                if (pam_auth(service, &up)) /* Succeeded */
                {
                    if (send_control(fd, RESPONSE_VERIFY_SUCCEEDED) == -1)
                    {
                        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "BACKGROUND: write error on response socket [2]");
                        goto done;
                    }
                }
                else /* Failed */
                {
                    if (send_control(fd, RESPONSE_VERIFY_FAILED) == -1)
                    {
                        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "BACKGROUND: write error on response socket [3]");
                        goto done;
                    }
                }
                plugin_secure_memzero(up.password, sizeof(up.password));
                break;

            case COMMAND_EXIT:
                goto done;

            case -1:
                plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "BACKGROUND: read error on command channel");
                goto done;

            default:
                plugin_log(PLOG_ERR, MODULE, "BACKGROUND: unknown command code: code=%d, exiting",
                           command);
                goto done;
        }
        plugin_secure_memzero(up.response, sizeof(up.response));
    }
done:
    plugin_secure_memzero(up.password, sizeof(up.password));
    plugin_secure_memzero(up.response, sizeof(up.response));
#ifdef USE_PAM_DLOPEN
    dlclose_pam();
#endif
    if (DEBUG(verb))
    {
        plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: EXIT");
    }

    return;
}
