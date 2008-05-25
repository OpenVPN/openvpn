/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2005 OpenVPN Solutions LLC <info@openvpn.net>
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
 * This file implements a simple OpenVPN plugin module which
 * will test deferred authentication.  Will run on Windows or *nix.
 *
 * See the README file for build instructions.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "openvpn-plugin.h"

/*
 * Our context, where we keep our state.
 */
struct plugin_context {
  int dummy;
};

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

/* used for safe printf of possible NULL strings */
static const char *
np (const char *str)
{
  if (str)
    return str;
  else
    return "[NULL]";
}

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v1 (unsigned int *type_mask, const char *argv[], const char *envp[])
{
  struct plugin_context *context;

  printf ("FUNC: openvpn_plugin_open_v1\n");

  /*
   * Allocate our context
   */
  context = (struct plugin_context *) calloc (1, sizeof (struct plugin_context));

  /*
   * Which callbacks to intercept.  We are only interested in
   * OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY, but we intercept all
   * the callbacks for illustration purposes, so we can show
   * the calling sequence via debug output.
   */
  *type_mask =
    OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_UP) |
    OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_DOWN) |
    OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_ROUTE_UP) |
    OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_IPCHANGE) |
    OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_TLS_VERIFY) |
    OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) |
    OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_CLIENT_CONNECT_V2) |
    OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_CLIENT_DISCONNECT) |
    OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_LEARN_ADDRESS) |
    OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_TLS_FINAL);

  return (openvpn_plugin_handle_t) context;
}

static int
auth_user_pass_verify (struct plugin_context *context, const char *argv[], const char *envp[])
{
  /* get username/password from envp string array */
  const char *username = get_env ("username", envp);
  const char *password = get_env ("password", envp);

  /* get auth_control_file filename from envp string array*/
  const char *auth_control_file = get_env ("auth_control_file", envp);

  printf ("DEFER u='%s' p='%s' acf='%s'\n",
	  np(username),
	  np(password),
	  np(auth_control_file));

  /* Authenticate asynchronously in 10 seconds */
  if (auth_control_file)
    {
      char buf[256];
      snprintf (buf, sizeof(buf), "( sleep 10 ; echo AUTH %s ; echo 1 >%s ) &",
		auth_control_file,
		auth_control_file);
      printf ("%s\n", buf);
      system (buf);
      return OPENVPN_PLUGIN_FUNC_DEFERRED;
    }
  else
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v1 (openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[])
{
  struct plugin_context *context = (struct plugin_context *) handle;
  switch (type)
    {
    case OPENVPN_PLUGIN_UP:
      printf ("OPENVPN_PLUGIN_UP\n");
      return OPENVPN_PLUGIN_FUNC_SUCCESS;
    case OPENVPN_PLUGIN_DOWN:
      printf ("OPENVPN_PLUGIN_DOWN\n");
      return OPENVPN_PLUGIN_FUNC_SUCCESS;
    case OPENVPN_PLUGIN_ROUTE_UP:
      printf ("OPENVPN_PLUGIN_ROUTE_UP\n");
      return OPENVPN_PLUGIN_FUNC_SUCCESS;
    case OPENVPN_PLUGIN_IPCHANGE:
      printf ("OPENVPN_PLUGIN_IPCHANGE\n");
      return OPENVPN_PLUGIN_FUNC_SUCCESS;
    case OPENVPN_PLUGIN_TLS_VERIFY:
      printf ("OPENVPN_PLUGIN_TLS_VERIFY\n");
      return OPENVPN_PLUGIN_FUNC_SUCCESS;
    case OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY:
      printf ("OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY\n");
      return auth_user_pass_verify (context, argv, envp);
    case OPENVPN_PLUGIN_CLIENT_CONNECT_V2:
      printf ("OPENVPN_PLUGIN_CLIENT_CONNECT_V2\n");
      return OPENVPN_PLUGIN_FUNC_SUCCESS;
    case OPENVPN_PLUGIN_CLIENT_DISCONNECT:
      printf ("OPENVPN_PLUGIN_CLIENT_DISCONNECT\n");
      return OPENVPN_PLUGIN_FUNC_SUCCESS;
    case OPENVPN_PLUGIN_LEARN_ADDRESS:
      printf ("OPENVPN_PLUGIN_LEARN_ADDRESS\n");
      return OPENVPN_PLUGIN_FUNC_SUCCESS;
    case OPENVPN_PLUGIN_TLS_FINAL:
      printf ("OPENVPN_PLUGIN_TLS_FINAL\n");
      return OPENVPN_PLUGIN_FUNC_SUCCESS;
    default:
      printf ("OPENVPN_PLUGIN_?\n");
      return OPENVPN_PLUGIN_FUNC_ERROR;
    }
}

OPENVPN_EXPORT void *
openvpn_plugin_client_constructor_v1 (openvpn_plugin_handle_t handle)
{
  printf ("FUNC: openvpn_plugin_client_constructor_v1\n");
  return malloc(1);
}

OPENVPN_EXPORT void
openvpn_plugin_client_destructor_v1 (openvpn_plugin_handle_t handle, void *per_client_context)
{
  printf ("FUNC: openvpn_plugin_client_destructor_v1\n");
  free (per_client_context);
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1 (openvpn_plugin_handle_t handle)
{
  struct plugin_context *context = (struct plugin_context *) handle;
  printf ("FUNC: openvpn_plugin_close_v1\n");
  free (context);
}
