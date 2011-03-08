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

/*
 * OpenVPN plugin module to do PAM authentication using a split
 * privilege model.
 */

#if DLOPEN_PAM
#include <dlfcn.h>
#include "pamdl.h"
#else
#include <security/pam_appl.h>
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

#include "openvpn-plugin.h"

#define DEBUG(verb) ((verb) >= 4)

/* Command codes for foreground -> background communication */
#define COMMAND_VERIFY 0
#define COMMAND_EXIT   1

/* Response codes for background -> foreground communication */
#define RESPONSE_INIT_SUCCEEDED   10
#define RESPONSE_INIT_FAILED      11
#define RESPONSE_VERIFY_SUCCEEDED 12
#define RESPONSE_VERIFY_FAILED    13

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

  const struct name_value_list *name_value_list;
};

/* Background process function */
static void pam_server (int fd, const char *service, int verb, const struct name_value_list *name_value_list);

/*  Read 'tosearch', replace all occurences of 'searchfor' with 'replacewith' and return
 *  a pointer to the NEW string.  Does not modify the input strings.  Will not enter an
 *  infinite loop with clever 'searchfor' and 'replacewith' strings.
 *  Daniel Johnson - Progman2000@usa.net / djohnson@progman.us
 */
static char *
searchandreplace(const char *tosearch, const char *searchfor, const char *replacewith)
{
  const char *searching=tosearch;
  char *scratch;
  char temp[strlen(tosearch)*10];
  temp[0]=0;

  if (!tosearch || !searchfor || !replacewith) return 0;
  if (!strlen(tosearch) || !strlen(searchfor) || !strlen(replacewith)) return 0;

  scratch = strstr(searching,searchfor);
  if (!scratch) return strdup(tosearch);

  while (scratch) {
    strncat(temp,searching,scratch-searching);
    strcat(temp,replacewith);

    searching=scratch+strlen(searchfor);
    scratch = strstr(searching,searchfor);
  }
  return strdup(temp);
}

/*
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 */
static const char *
get_env (const char *name, const char *envp[])
{
  if (envp)
    {
      int i;
      const int namelen = strlen (name);
      for (i = 0; envp[i]; ++i)
	{
	  if (!strncmp (envp[i], name, namelen))
	    {
	      const char *cp = envp[i] + namelen;
	      if (*cp == '=')
		return cp + 1;
	    }
	}
    }
  return NULL;
}

/*
 * Return the length of a string array
 */
static int
string_array_len (const char *array[])
{
  int i = 0;
  if (array)
    {
      while (array[i])
	++i;
    }
  return i;
}

/*
 * Socket read/write functions.
 */

static int
recv_control (int fd)
{
  unsigned char c;
  const ssize_t size = read (fd, &c, sizeof (c));
  if (size == sizeof (c))
    return c;
  else
    {
      /*fprintf (stderr, "AUTH-PAM: DEBUG recv_control.read=%d\n", (int)size);*/
      return -1;
    }
}

static int
send_control (int fd, int code)
{
  unsigned char c = (unsigned char) code;
  const ssize_t size = write (fd, &c, sizeof (c));
  if (size == sizeof (c))
    return (int) size;
  else
    return -1;
}

static int
recv_string (int fd, char *buffer, int len)
{
  if (len > 0)
    {
      ssize_t size;
      memset (buffer, 0, len);
      size = read (fd, buffer, len);
      buffer[len-1] = 0;
      if (size >= 1)
	return (int)size;
    }
  return -1;
}

static int
send_string (int fd, const char *string)
{
  const int len = strlen (string) + 1;
  const ssize_t size = write (fd, string, len);
  if (size == len)
    return (int) size;
  else
    return -1;
}

#ifdef DO_DAEMONIZE

/*
 * Daemonize if "daemon" env var is true.
 * Preserve stderr across daemonization if
 * "daemon_log_redirect" env var is true.
 */
static void
daemonize (const char *envp[])
{
  const char *daemon_string = get_env ("daemon", envp);
  if (daemon_string && daemon_string[0] == '1')
    {
      const char *log_redirect = get_env ("daemon_log_redirect", envp);
      int fd = -1;
      if (log_redirect && log_redirect[0] == '1')
	fd = dup (2);
      if (daemon (0, 0) < 0)
	{
	  fprintf (stderr, "AUTH-PAM: daemonization failed\n");
	}
      else if (fd >= 3)
	{
	  dup2 (fd, 2);
	  close (fd);
	}
    }
}

#endif

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
close_fds_except (int keep)
{
  int i;
  closelog ();
  for (i = 3; i <= 100; ++i)
    {
      if (i != keep)
	close (i);
    }
}

/*
 * Usually we ignore signals, because our parent will
 * deal with them.
 */
static void
set_signals (void)
{
  signal (SIGTERM, SIG_DFL);

  signal (SIGINT, SIG_IGN);
  signal (SIGHUP, SIG_IGN);
  signal (SIGUSR1, SIG_IGN);
  signal (SIGUSR2, SIG_IGN);
  signal (SIGPIPE, SIG_IGN);
}

/*
 * Return 1 if query matches match.
 */
static int
name_value_match (const char *query, const char *match)
{
  while (!isalnum (*query))
    {
      if (*query == '\0')
	return 0;
      ++query;
    }
  return strncasecmp (match, query, strlen (match)) == 0;
}

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v1 (unsigned int *type_mask, const char *argv[], const char *envp[])
{
  pid_t pid;
  int fd[2];

  struct auth_pam_context *context;
  struct name_value_list name_value_list;

  const int base_parms = 2;

  /*
   * Allocate our context
   */
  context = (struct auth_pam_context *) calloc (1, sizeof (struct auth_pam_context));
  if (!context)
    goto error;
  context->foreground_fd = -1;

  /*
   * Intercept the --auth-user-pass-verify callback.
   */
  *type_mask = OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

  /*
   * Make sure we have two string arguments: the first is the .so name,
   * the second is the PAM service type.
   */
  if (string_array_len (argv) < base_parms)
    {
      fprintf (stderr, "AUTH-PAM: need PAM service parameter\n");
      goto error;
    }

  /*
   * See if we have optional name/value pairs to match against
   * PAM module queried fields in the conversation function.
   */
  name_value_list.len = 0;
  if (string_array_len (argv) > base_parms)
    {
      const int nv_len = string_array_len (argv) - base_parms;
      int i;

      if ((nv_len & 1) == 1 || (nv_len / 2) > N_NAME_VALUE)
	{
	  fprintf (stderr, "AUTH-PAM: bad name/value list length\n");
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
    const char *verb_string = get_env ("verb", envp);
    if (verb_string)
      context->verb = atoi (verb_string);
  }

  /*
   * Make a socket for foreground and background processes
   * to communicate.
   */
  if (socketpair (PF_UNIX, SOCK_DGRAM, 0, fd) == -1)
    {
      fprintf (stderr, "AUTH-PAM: socketpair call failed\n");
      goto error;
    }

  /*
   * Fork off the privileged process.  It will remain privileged
   * even after the foreground process drops its privileges.
   */
  pid = fork ();

  if (pid)
    {
      int status;

      /*
       * Foreground Process
       */

      context->background_pid = pid;

      /* close our copy of child's socket */
      close (fd[1]);

      /* don't let future subprocesses inherit child socket */
      if (fcntl (fd[0], F_SETFD, FD_CLOEXEC) < 0)
	fprintf (stderr, "AUTH-PAM: Set FD_CLOEXEC flag on socket file descriptor failed\n");

      /* wait for background child process to initialize */
      status = recv_control (fd[0]);
      if (status == RESPONSE_INIT_SUCCEEDED)
	{
	  context->foreground_fd = fd[0];
	  return (openvpn_plugin_handle_t) context;
	}
    }
  else
    {
      /*
       * Background Process
       */

      /* close all parent fds except our socket back to parent */
      close_fds_except (fd[1]);

      /* Ignore most signals (the parent will receive them) */
      set_signals ();

#ifdef DO_DAEMONIZE
      /* Daemonize if --daemon option is set. */
      daemonize (envp);
#endif

      /* execute the event loop */
      pam_server (fd[1], argv[1], context->verb, &name_value_list);

      close (fd[1]);

      exit (0);
      return 0; /* NOTREACHED */
    }

 error:
  if (context)
    free (context);
  return NULL;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v1 (openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[])
{
  struct auth_pam_context *context = (struct auth_pam_context *) handle;

  if (type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY && context->foreground_fd >= 0)
    {
      /* get username/password from envp string array */
      const char *username = get_env ("username", envp);
      const char *password = get_env ("password", envp);

      if (username && strlen (username) > 0 && password)
	{
	  if (send_control (context->foreground_fd, COMMAND_VERIFY) == -1
	      || send_string (context->foreground_fd, username) == -1
	      || send_string (context->foreground_fd, password) == -1)
	    {
	      fprintf (stderr, "AUTH-PAM: Error sending auth info to background process\n");
	    }
	  else
	    {
	      const int status = recv_control (context->foreground_fd);
	      if (status == RESPONSE_VERIFY_SUCCEEDED)
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
	      if (status == -1)
		fprintf (stderr, "AUTH-PAM: Error receiving auth confirmation from background process\n");
	    }
	}
    }
  return OPENVPN_PLUGIN_FUNC_ERROR;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1 (openvpn_plugin_handle_t handle)
{
  struct auth_pam_context *context = (struct auth_pam_context *) handle;

  if (DEBUG (context->verb))
    fprintf (stderr, "AUTH-PAM: close\n");

  if (context->foreground_fd >= 0)
    {
      /* tell background process to exit */
      if (send_control (context->foreground_fd, COMMAND_EXIT) == -1)
	fprintf (stderr, "AUTH-PAM: Error signaling background process to exit\n");

      /* wait for background process to exit */
      if (context->background_pid > 0)
	waitpid (context->background_pid, NULL, 0);

      close (context->foreground_fd);
      context->foreground_fd = -1;
    }

  free (context);
}

OPENVPN_EXPORT void
openvpn_plugin_abort_v1 (openvpn_plugin_handle_t handle)
{
  struct auth_pam_context *context = (struct auth_pam_context *) handle;

  /* tell background process to exit */
  if (context && context->foreground_fd >= 0)
    {
      send_control (context->foreground_fd, COMMAND_EXIT);
      close (context->foreground_fd);
      context->foreground_fd = -1;
    }
}

/*
 * PAM conversation function
 */
static int
my_conv (int n, const struct pam_message **msg_array,
	 struct pam_response **response_array, void *appdata_ptr)
{
  const struct user_pass *up = ( const struct user_pass *) appdata_ptr;
  struct pam_response *aresp;
  int i;
  int ret = PAM_SUCCESS;

  *response_array = NULL;

  if (n <= 0 || n > PAM_MAX_NUM_MSG)
    return (PAM_CONV_ERR);
  if ((aresp = calloc (n, sizeof *aresp)) == NULL)
    return (PAM_BUF_ERR);

  /* loop through each PAM-module query */
  for (i = 0; i < n; ++i)
    {
      const struct pam_message *msg = msg_array[i];
      aresp[i].resp_retcode = 0;
      aresp[i].resp = NULL;

      if (DEBUG (up->verb))
	{
	  fprintf (stderr, "AUTH-PAM: BACKGROUND: my_conv[%d] query='%s' style=%d\n",
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

	      if (name_value_match (msg->msg, match_name))
		{
		  /* found name/value match */
		  aresp[i].resp = NULL;

		  if (DEBUG (up->verb))
		    fprintf (stderr, "AUTH-PAM: BACKGROUND: name match found, query/match-string ['%s', '%s'] = '%s'\n",
			     msg->msg,
			     match_name,
			     match_value);

		  if (strstr(match_value, "USERNAME"))
		    aresp[i].resp = searchandreplace(match_value, "USERNAME", up->username);
		  else if (strstr(match_value, "PASSWORD"))
		    aresp[i].resp = searchandreplace(match_value, "PASSWORD", up->password);
		  else
		    aresp[i].resp = strdup (match_value);

		  if (aresp[i].resp == NULL)
		    ret = PAM_CONV_ERR;
		  break;
		}
	    }

	  if (j == list->len)
	    ret = PAM_CONV_ERR;
	}
      else
	{
	  /* use PAM_PROMPT_ECHO_x hints */
	  switch (msg->msg_style)
	    {
	    case PAM_PROMPT_ECHO_OFF:
	      aresp[i].resp = strdup (up->password);
	      if (aresp[i].resp == NULL)
		ret = PAM_CONV_ERR;
	      break;

	    case PAM_PROMPT_ECHO_ON:
	      aresp[i].resp = strdup (up->username);
	      if (aresp[i].resp == NULL)
		ret = PAM_CONV_ERR;
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
    *response_array = aresp;
  return ret;
}

/*
 * Return 1 if authenticated and 0 if failed.
 * Called once for every username/password
 * to be authenticated.
 */
static int
pam_auth (const char *service, const struct user_pass *up)
{
  struct pam_conv conv;
  pam_handle_t *pamh = NULL;
  int status = PAM_SUCCESS;
  int ret = 0;
  const int name_value_list_provided = (up->name_value_list && up->name_value_list->len > 0);

  /* Initialize PAM */
  conv.conv = my_conv;
  conv.appdata_ptr = (void *)up;
  status = pam_start (service, name_value_list_provided ? NULL : up->username, &conv, &pamh);
  if (status == PAM_SUCCESS)
    {
      /* Call PAM to verify username/password */
      status = pam_authenticate(pamh, 0);
      if (status == PAM_SUCCESS)
	status = pam_acct_mgmt (pamh, 0);
      if (status == PAM_SUCCESS)
	ret = 1;

      /* Output error message if failed */
      if (!ret)
	{
	  fprintf (stderr, "AUTH-PAM: BACKGROUND: user '%s' failed to authenticate: %s\n",
		   up->username,
		   pam_strerror (pamh, status));
	}

      /* Close PAM */
      pam_end (pamh, status);      
    }

  return ret;
}

/*
 * Background process -- runs with privilege.
 */
static void
pam_server (int fd, const char *service, int verb, const struct name_value_list *name_value_list)
{
  struct user_pass up;
  int command;
#if DLOPEN_PAM
  static const char pam_so[] = "libpam.so";
#endif

  /*
   * Do initialization
   */
  if (DEBUG (verb))
    fprintf (stderr, "AUTH-PAM: BACKGROUND: INIT service='%s'\n", service);

#if DLOPEN_PAM
  /*
   * Load PAM shared object
   */
  if (!dlopen_pam (pam_so))
    {
      fprintf (stderr, "AUTH-PAM: BACKGROUND: could not load PAM lib %s: %s\n", pam_so, dlerror());
      send_control (fd, RESPONSE_INIT_FAILED);
      goto done;
    }
#endif

  /*
   * Tell foreground that we initialized successfully
   */
  if (send_control (fd, RESPONSE_INIT_SUCCEEDED) == -1)
    {
      fprintf (stderr, "AUTH-PAM: BACKGROUND: write error on response socket [1]\n");
      goto done;
    }

  /*
   * Event loop
   */
  while (1)
    {
      memset (&up, 0, sizeof (up));
      up.verb = verb;
      up.name_value_list = name_value_list;

      /* get a command from foreground process */
      command = recv_control (fd);

      if (DEBUG (verb))
	fprintf (stderr, "AUTH-PAM: BACKGROUND: received command code: %d\n", command);

      switch (command)
	{
	case COMMAND_VERIFY:
	  if (recv_string (fd, up.username, sizeof (up.username)) == -1
	      || recv_string (fd, up.password, sizeof (up.password)) == -1)
	    {
	      fprintf (stderr, "AUTH-PAM: BACKGROUND: read error on command channel: code=%d, exiting\n",
		       command);
	      goto done;
	    }

	  if (DEBUG (verb))
	    {
#if 0
	      fprintf (stderr, "AUTH-PAM: BACKGROUND: USER/PASS: %s/%s\n",
		       up.username, up.password);
#else
	      fprintf (stderr, "AUTH-PAM: BACKGROUND: USER: %s\n", up.username);
#endif
	    }

	  if (pam_auth (service, &up)) /* Succeeded */
	    {
	      if (send_control (fd, RESPONSE_VERIFY_SUCCEEDED) == -1)
		{
		  fprintf (stderr, "AUTH-PAM: BACKGROUND: write error on response socket [2]\n");
		  goto done;
		}
	    }
	  else /* Failed */
	    {
	      if (send_control (fd, RESPONSE_VERIFY_FAILED) == -1)
		{
		  fprintf (stderr, "AUTH-PAM: BACKGROUND: write error on response socket [3]\n");
		  goto done;
		}
	    }
	  break;

	case COMMAND_EXIT:
	  goto done;

	case -1:
	  fprintf (stderr, "AUTH-PAM: BACKGROUND: read error on command channel\n");
	  goto done;

	default:
	  fprintf (stderr, "AUTH-PAM: BACKGROUND: unknown command code: code=%d, exiting\n",
		   command);
	  goto done;
	}
    }
 done:

#if DLOPEN_PAM
  dlclose_pam ();
#endif
  if (DEBUG (verb))
    fprintf (stderr, "AUTH-PAM: BACKGROUND: EXIT\n");

  return;
}
