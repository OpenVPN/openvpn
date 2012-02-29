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
 * This file implements a simple OpenVPN plugin module which
 * will examine the username/password provided by a client,
 * and make an accept/deny determination.  Will run
 * on Windows or *nix.
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
  const char *username;
  const char *password;
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

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v1 (unsigned int *type_mask, const char *argv[], const char *envp[])
{
  struct plugin_context *context;

  /*
   * Allocate our context
   */
  context = (struct plugin_context *) calloc (1, sizeof (struct plugin_context));

  /*
   * Set the username/password we will require.
   */
  context->username = "foo";
  context->password = "bar";

  /*
   * We are only interested in intercepting the
   * --auth-user-pass-verify callback.
   */
  *type_mask = OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

  return (openvpn_plugin_handle_t) context;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v1 (openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[])
{
  struct plugin_context *context = (struct plugin_context *) handle;

  /* get username/password from envp string array */
  const char *username = get_env ("username", envp);
  const char *password = get_env ("password", envp);

  /* check entered username/password against what we require */
  if (username && !strcmp (username, context->username)
      && password && !strcmp (password, context->password))
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
  else
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1 (openvpn_plugin_handle_t handle)
{
  struct plugin_context *context = (struct plugin_context *) handle;
  free (context);
}
