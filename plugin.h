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
 * plug-in support, using dynamically loaded libraries
 */

#ifndef OPENVPN_PLUGIN_H
#define OPENVPN_PLUGIN_H

#include "openvpn-plugin.h"

#ifdef ENABLE_PLUGIN

#include "misc.h"

#define MAX_PLUGINS 32

struct plugin_option {
  const char *so_pathname;
  const char *args;
};

struct plugin_option_list {
  int n;
  struct plugin_option plugins[MAX_PLUGINS];
};

struct plugin {
  const char *so_pathname;
  unsigned int plugin_type_mask;
#if defined(USE_LIBDL)
  void *handle;
#elif defined(USE_LOAD_LIBRARY)
  HMODULE module;
#endif
  openvpn_plugin_open_v1 open;
  openvpn_plugin_func_v1 func;
  openvpn_plugin_close_v1 close;
  openvpn_plugin_abort_v1 abort;

  openvpn_plugin_handle_t plugin_handle;
};

struct plugin_list {
  int n;
  struct plugin plugins[MAX_PLUGINS];
};

struct plugin_option_list *plugin_option_list_new (struct gc_arena *gc);
bool plugin_option_list_add (struct plugin_option_list *list, const char *so_pathname, const char *args);

#ifdef ENABLE_DEBUG
void plugin_option_list_print (const struct plugin_option_list *list, int msglevel);
#endif

struct plugin_list *plugin_list_open (const struct plugin_option_list *list, const struct env_set *es);
int plugin_call (const struct plugin_list *pl, const int type, const char *args, struct env_set *es);
void plugin_list_close (struct plugin_list *pl);
bool plugin_defined (const struct plugin_list *pl, const int type);

#else

struct plugin_list { int dummy; };

static inline bool
plugin_defined (const struct plugin_list *pl, const int type)
{
  return false;
}

static inline int
plugin_call (const struct plugin_list *pl, const int type, const char *args, struct env_set *es)
{
  return 0;
}

#endif /* ENABLE_PLUGIN */

#endif /* OPENVPN_PLUGIN_H */
