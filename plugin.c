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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#ifdef ENABLE_PLUGIN

#include "buffer.h"
#include "error.h"
#include "misc.h"
#include "plugin.h"

#include "memdbg.h"

#define PLUGIN_SYMBOL_REQUIRED (1<<0)

/* used only for program aborts */
static struct plugin_list *static_plugin_list = NULL; /* GLOBAL */

static void
plugin_show_string_array (int msglevel, const char *name, const char *array[])
{
  int i;
  for (i = 0; array[i]; ++i)
    msg (msglevel, "%s[%d] = '%s'", name, i, array[i]);
}

static void
plugin_show_args_env (int msglevel, const char *argv[], const char *envp[])
{
  if (check_debug_level (msglevel))
    {
      plugin_show_string_array (msglevel, "ARGV", argv);
      plugin_show_string_array (msglevel, "ENVP", envp);
    }
}

static const char *
plugin_type_name (const int type)
{
  switch (type)
    {
    case OPENVPN_PLUGIN_UP:
      return "PLUGIN_UP";
    case OPENVPN_PLUGIN_DOWN:
      return "PLUGIN_DOWN";
    case OPENVPN_PLUGIN_ROUTE_UP:
      return "PLUGIN_ROUTE_UP";
    case OPENVPN_PLUGIN_IPCHANGE:
      return "PLUGIN_IPCHANGE";
    case OPENVPN_PLUGIN_TLS_VERIFY:
      return "PLUGIN_TLS_VERIFY";
    case OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY:
      return "PLUGIN_AUTH_USER_PASS_VERIFY";
    case OPENVPN_PLUGIN_CLIENT_CONNECT:
      return "PLUGIN_CLIENT_CONNECT";
    case OPENVPN_PLUGIN_CLIENT_DISCONNECT:
      return "PLUGIN_CLIENT_DISCONNECT";
    case OPENVPN_PLUGIN_LEARN_ADDRESS:
      return "PLUGIN_LEARN_ADDRESS";
    default:
      return "PLUGIN_???";
    }
}

static const char *
plugin_mask_string (const unsigned int type_mask, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (256, gc);
  bool first = true;
  int i;

  for (i = 0; i < OPENVPN_PLUGIN_N; ++i)
    {
      if (OPENVPN_PLUGIN_MASK (i) & type_mask)
	{
	  if (!first)
	    buf_printf (&out, "|");
	  buf_printf (&out, "%s", plugin_type_name (i));
	  first = false;
	}
    }
  return BSTR (&out);
}

static inline unsigned int
plugin_supported_types (void)
{
  return ((1<<OPENVPN_PLUGIN_N)-1);
}

struct plugin_option_list *
plugin_option_list_new (struct gc_arena *gc)
{
  struct plugin_option_list *ret;
  ALLOC_OBJ_CLEAR_GC (ret, struct plugin_option_list, gc);
  return ret;
}

bool
plugin_option_list_add (struct plugin_option_list *list, const char *so_pathname, const char *args)
{
  if (list->n < MAX_PLUGINS)
    {
      struct plugin_option *o = &list->plugins[list->n++];
      o->so_pathname = so_pathname;
      o->args = args;
      return true;
    }
  else
    return false;
}

#ifdef ENABLE_DEBUG
void
plugin_option_list_print (const struct plugin_option_list *list, int msglevel)
{
  int i;
  for (i = 0; i < list->n; ++i)
    {
      const struct plugin_option *o = &list->plugins[i];
      msg (msglevel, "  plugin[%d] %s '%s'", i, o->so_pathname, o->args);
    }
}
#endif

#if defined(USE_LIBDL)

static void
libdl_resolve_symbol (void *handle, void **dest, const char *symbol, const char *plugin_name, const unsigned int flags)
{
  *dest = dlsym (handle, symbol);
  if ((flags & PLUGIN_SYMBOL_REQUIRED) && !*dest)
    msg (M_FATAL, "PLUGIN: could not find required symbol '%s' in plugin shared object %s: %s", symbol, plugin_name, dlerror());
}

#elif defined(USE_LOAD_LIBRARY)

static void
dll_resolve_symbol (HMODULE module, void **dest, const char *symbol, const char *plugin_name, const unsigned int flags)
{
  *dest = GetProcAddress (module, symbol);
  if ((flags & PLUGIN_SYMBOL_REQUIRED) && !*dest)
    msg (M_FATAL, "PLUGIN: could not find required symbol '%s' in plugin DLL %s", symbol, plugin_name);
}

#endif

static void
plugin_init_item (struct plugin *p, const struct plugin_option *o, const char **envp)
{
  struct gc_arena gc = gc_new ();
  const char **argv = make_arg_array (o->so_pathname, o->args, &gc);
  p->so_pathname = o->so_pathname;
  p->plugin_type_mask = plugin_supported_types ();

#if defined(USE_LIBDL)
  p->handle = dlopen (p->so_pathname, RTLD_NOW);
  if (!p->handle)
    msg (M_ERR, "PLUGIN_INIT: could not load plugin shared object %s: %s", p->so_pathname, dlerror());
  libdl_resolve_symbol (p->handle, (void*)&p->open,  "openvpn_plugin_open_v1", p->so_pathname, PLUGIN_SYMBOL_REQUIRED);
  libdl_resolve_symbol (p->handle, (void*)&p->func,  "openvpn_plugin_func_v1", p->so_pathname, PLUGIN_SYMBOL_REQUIRED);
  libdl_resolve_symbol (p->handle, (void*)&p->close, "openvpn_plugin_close_v1", p->so_pathname, PLUGIN_SYMBOL_REQUIRED);
  libdl_resolve_symbol (p->handle, (void*)&p->abort, "openvpn_plugin_abort_v1", p->so_pathname, 0);
#elif defined(USE_LOAD_LIBRARY)
  p->module = LoadLibrary (p->so_pathname);
  if (!p->module)
    msg (M_ERR, "PLUGIN_INIT: could not load plugin DLL: %s", p->so_pathname);
  dll_resolve_symbol (p->module, (void*)&p->open,  "openvpn_plugin_open_v1", p->so_pathname, PLUGIN_SYMBOL_REQUIRED);
  dll_resolve_symbol (p->module, (void*)&p->func,  "openvpn_plugin_func_v1", p->so_pathname, PLUGIN_SYMBOL_REQUIRED);
  dll_resolve_symbol (p->module, (void*)&p->close, "openvpn_plugin_close_v1", p->so_pathname, PLUGIN_SYMBOL_REQUIRED);
  dll_resolve_symbol (p->module, (void*)&p->abort, "openvpn_plugin_abort_v1", p->so_pathname, 0);
#endif

  dmsg (D_PLUGIN_DEBUG, "PLUGIN_INIT: PRE");
  plugin_show_args_env (D_PLUGIN_DEBUG, argv, envp);

  /*
   * Call the plugin initialization
   */
  p->plugin_handle = (*p->open)(&p->plugin_type_mask, argv, envp);

  msg (D_PLUGIN, "PLUGIN_INIT: POST %s '%s' intercepted=%s",
       p->so_pathname,
       o->args ? o->args : "[NULL]",
       plugin_mask_string (p->plugin_type_mask, &gc));

  if ((p->plugin_type_mask | plugin_supported_types()) != plugin_supported_types())
    msg (M_FATAL, "PLUGIN_INIT: plugin %s expressed interest in unsupported plugin types: [want=0x%08x, have=0x%08x]",
	 p->so_pathname,
	 p->plugin_type_mask,
	 plugin_supported_types());

  if (p->plugin_handle == NULL)
    msg (M_FATAL, "PLUGIN_INIT: plugin initialization function failed: %s",
	 p->so_pathname);

  gc_free (&gc);
}

static int
plugin_call_item (const struct plugin *p, const int type, const char *args, const char **envp)
{
  int status = OPENVPN_PLUGIN_FUNC_SUCCESS;

  if (p->plugin_type_mask & OPENVPN_PLUGIN_MASK (type))
    {
      struct gc_arena gc = gc_new ();
      const char **argv = make_arg_array (p->so_pathname, args, &gc);

      dmsg (D_PLUGIN_DEBUG, "PLUGIN_CALL: PRE type=%s", plugin_type_name (type));
      plugin_show_args_env (D_PLUGIN_DEBUG, argv, envp);

      /*
       * Call the plugin work function
       */
      status = (*p->func)(p->plugin_handle, type, argv, envp);

      msg (D_PLUGIN, "PLUGIN_CALL: POST %s/%s status=%d",
	   p->so_pathname,
	   plugin_type_name (type),
	   status);

      if (status != OPENVPN_PLUGIN_FUNC_SUCCESS)
	msg (M_WARN, "PLUGIN_CALL: plugin function %s failed with status %d: %s",
	     plugin_type_name (type),
	     status,
	     p->so_pathname);

      gc_free (&gc);
    }
  return status;
}

static void
plugin_close_item (const struct plugin *p)
{
  msg (D_PLUGIN, "PLUGIN_CLOSE: %s", p->so_pathname);

  /*
   * Call the plugin close function
   */
  (*p->close)(p->plugin_handle);

#if defined(USE_LIBDL)
  if (dlclose (p->handle))
    msg (M_WARN, "PLUGIN_CLOSE: dlclose() failed on plugin: %s", p->so_pathname);
#elif defined(USE_LOAD_LIBRARY)
  if (!FreeLibrary (p->module))
    msg (M_WARN, "PLUGIN_CLOSE: FreeLibrary() failed on plugin: %s", p->so_pathname);
#endif
}

static void
plugin_abort_item (const struct plugin *p)
{
  /*
   * Call the plugin abort function
   */
  if (p->abort)
    (*p->abort)(p->plugin_handle);
}

struct plugin_list *
plugin_list_open (const struct plugin_option_list *list, const struct env_set *es)
{
  struct gc_arena gc = gc_new ();
  int i;
  struct plugin_list *pl;
  const char **envp;

  ALLOC_OBJ_CLEAR (pl, struct plugin_list);
  static_plugin_list = pl;

  envp = make_env_array (es, &gc);

  for (i = 0; i < list->n; ++i)
    {
      plugin_init_item (&pl->plugins[i], &list->plugins[i], envp);
      pl->n = i + 1;
    }

  gc_free (&gc);
  return pl;
}

int
plugin_call (const struct plugin_list *pl, const int type, const char *args, struct env_set *es)
{
  int count = 0;

  if (plugin_defined (pl, type))
    {
      struct gc_arena gc = gc_new ();
      int i;
      const char **envp;
      
      mutex_lock_static (L_PLUGIN);

      setenv_del (es, "script_type");
      envp = make_env_array (es, &gc);

      for (i = 0; i < pl->n; ++i)
	{
	  if (!plugin_call_item (&pl->plugins[i], type, args, envp))
	    ++count;
	}

      mutex_unlock_static (L_PLUGIN);

      gc_free (&gc);
    }

  return count == pl->n ? 0 : 1; /* if any one plugin in the chain failed, return failure (1) */
}

void
plugin_list_close (struct plugin_list *pl)
{
  static_plugin_list = NULL;
  if (pl)
    {
      int i;

      for (i = 0; i < pl->n; ++i)
	plugin_close_item (&pl->plugins[i]);
      free (pl);
    }
}

void
plugin_abort (void)
{
  struct plugin_list *pl = static_plugin_list;
  static_plugin_list = NULL;
  if (pl)
    {
      int i;

      for (i = 0; i < pl->n; ++i)
	plugin_abort_item (&pl->plugins[i]);
    }
}

bool
plugin_defined (const struct plugin_list *pl, const int type)
{
  bool ret = false;
  if (pl)
    {
      int i;
      const unsigned int mask = OPENVPN_PLUGIN_MASK (type);
      for (i = 0; i < pl->n; ++i)
	{
	  if (pl->plugins[i].plugin_type_mask & mask)
	    {
	      ret = true;
	      break;
	    }
	}
    }
  return ret;
}

#else
static void dummy(void) {}
#endif /* ENABLE_PLUGIN */
