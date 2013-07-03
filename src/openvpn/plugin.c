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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#ifdef ENABLE_PLUGIN

#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#include "buffer.h"
#include "error.h"
#include "misc.h"
#include "plugin.h"
#include "ssl_backend.h"
#include "win32.h"
#include "memdbg.h"

#define PLUGIN_SYMBOL_REQUIRED (1<<0)

/* used only for program aborts */
static struct plugin_common *static_plugin_common = NULL; /* GLOBAL */

static void
plugin_show_string_array (int msglevel, const char *name, const char *array[])
{
  int i;
  for (i = 0; array[i]; ++i)
    {
      if (env_safe_to_print (array[i]))
	msg (msglevel, "%s[%d] = '%s'", name, i, array[i]);
    }
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
    case OPENVPN_PLUGIN_CLIENT_CONNECT_V2:
      return "PLUGIN_CLIENT_CONNECT";
    case OPENVPN_PLUGIN_CLIENT_DISCONNECT:
      return "PLUGIN_CLIENT_DISCONNECT";
    case OPENVPN_PLUGIN_LEARN_ADDRESS:
      return "PLUGIN_LEARN_ADDRESS";
    case OPENVPN_PLUGIN_TLS_FINAL:
      return "PLUGIN_TLS_FINAL";
    case OPENVPN_PLUGIN_ENABLE_PF:
      return "PLUGIN_ENABLE_PF";
    case OPENVPN_PLUGIN_ROUTE_PREDOWN:
      return "PLUGIN_ROUTE_PREDOWN";
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
plugin_option_list_add (struct plugin_option_list *list, char **p, struct gc_arena *gc)
{
  if (list->n < MAX_PLUGINS)
    {
      struct plugin_option *o = &list->plugins[list->n++];
      o->argv = make_extended_arg_array (p, gc);
      if (o->argv[0])
	o->so_pathname = o->argv[0];
      return true;
    }
  else
    return false;
}

#ifndef ENABLE_SMALL
void
plugin_option_list_print (const struct plugin_option_list *list, int msglevel)
{
  int i;
  struct gc_arena gc = gc_new ();

  for (i = 0; i < list->n; ++i)
    {
      const struct plugin_option *o = &list->plugins[i];
      msg (msglevel, "  plugin[%d] %s '%s'", i, o->so_pathname, print_argv (o->argv, &gc, PA_BRACKET));
    }

  gc_free (&gc);
}
#endif

#ifndef WIN32

static void
libdl_resolve_symbol (void *handle, void **dest, const char *symbol, const char *plugin_name, const unsigned int flags)
{
  *dest = dlsym (handle, symbol);
  if ((flags & PLUGIN_SYMBOL_REQUIRED) && !*dest)
    msg (M_FATAL, "PLUGIN: could not find required symbol '%s' in plugin shared object %s: %s", symbol, plugin_name, dlerror());
}

#else

static void
dll_resolve_symbol (HMODULE module, void **dest, const char *symbol, const char *plugin_name, const unsigned int flags)
{
  *dest = GetProcAddress (module, symbol);
  if ((flags & PLUGIN_SYMBOL_REQUIRED) && !*dest)
    msg (M_FATAL, "PLUGIN: could not find required symbol '%s' in plugin DLL %s", symbol, plugin_name);
}

#endif

static void
plugin_init_item (struct plugin *p, const struct plugin_option *o)
{
  struct gc_arena gc = gc_new ();
  bool rel = false;

  p->so_pathname = o->so_pathname;
  p->plugin_type_mask = plugin_supported_types ();

#ifndef WIN32

  p->handle = NULL;
#if defined(PLUGIN_LIBDIR)
  if (!absolute_pathname (p->so_pathname))
    {
      char full[PATH_MAX];

      openvpn_snprintf (full, sizeof(full), "%s/%s", PLUGIN_LIBDIR, p->so_pathname);
      p->handle = dlopen (full, RTLD_NOW);
#if defined(ENABLE_PLUGIN_SEARCH)
      if (!p->handle)
	{
	  rel = true;
	  p->handle = dlopen (p->so_pathname, RTLD_NOW);
	}
#endif
    }
  else
#endif
    {
      rel = !absolute_pathname (p->so_pathname);
      p->handle = dlopen (p->so_pathname, RTLD_NOW);
    }
  if (!p->handle)
    msg (M_ERR, "PLUGIN_INIT: could not load plugin shared object %s: %s", p->so_pathname, dlerror());

# define PLUGIN_SYM(var, name, flags) libdl_resolve_symbol (p->handle, (void*)&p->var, name, p->so_pathname, flags)

#else

  rel = !absolute_pathname (p->so_pathname);
  p->module = LoadLibraryW (wide_string (p->so_pathname, &gc));
  if (!p->module)
    msg (M_ERR, "PLUGIN_INIT: could not load plugin DLL: %s", p->so_pathname);

# define PLUGIN_SYM(var, name, flags) dll_resolve_symbol (p->module, (void*)&p->var, name, p->so_pathname, flags)

#endif

  PLUGIN_SYM (open1, "openvpn_plugin_open_v1", 0);
  PLUGIN_SYM (open2, "openvpn_plugin_open_v2", 0);
  PLUGIN_SYM (open3, "openvpn_plugin_open_v3", 0);
  PLUGIN_SYM (func1, "openvpn_plugin_func_v1", 0);
  PLUGIN_SYM (func2, "openvpn_plugin_func_v2", 0);
  PLUGIN_SYM (func3, "openvpn_plugin_func_v3", 0);
  PLUGIN_SYM (close, "openvpn_plugin_close_v1", PLUGIN_SYMBOL_REQUIRED);
  PLUGIN_SYM (abort, "openvpn_plugin_abort_v1", 0);
  PLUGIN_SYM (client_constructor, "openvpn_plugin_client_constructor_v1", 0);
  PLUGIN_SYM (client_destructor, "openvpn_plugin_client_destructor_v1", 0);
  PLUGIN_SYM (min_version_required, "openvpn_plugin_min_version_required_v1", 0);
  PLUGIN_SYM (initialization_point, "openvpn_plugin_select_initialization_point_v1", 0);

  if (!p->open1 && !p->open2 && !p->open3)
    msg (M_FATAL, "PLUGIN: symbol openvpn_plugin_open_vX is undefined in plugin: %s", p->so_pathname);

  if (!p->func1 && !p->func2 && !p->func3)
    msg (M_FATAL, "PLUGIN: symbol openvpn_plugin_func_vX is undefined in plugin: %s", p->so_pathname);

  /*
   * Verify that we are sufficiently up-to-date to handle the plugin
   */
  if (p->min_version_required)
    {
      const int plugin_needs_version = (*p->min_version_required)();
      if (plugin_needs_version > OPENVPN_PLUGIN_VERSION)
	msg (M_FATAL, "PLUGIN_INIT: plugin needs interface version %d, but this version of OpenVPN only supports version %d: %s",
	     plugin_needs_version,
	     OPENVPN_PLUGIN_VERSION,
	     p->so_pathname);
    }

  if (p->initialization_point)
    p->requested_initialization_point = (*p->initialization_point)();
  else
    p->requested_initialization_point = OPENVPN_PLUGIN_INIT_PRE_DAEMON;

  if (rel)
    msg (M_WARN, "WARNING: plugin '%s' specified by a relative pathname -- using an absolute pathname would be more secure", p->so_pathname);

  p->initialized = true;

  gc_free (&gc);
}

static void
plugin_vlog (openvpn_plugin_log_flags_t flags, const char *name, const char *format, va_list arglist)
{
  unsigned int msg_flags;

  if (!format)
    return;

  if (!name || name[0] == '\0')
    {
      msg (D_PLUGIN_DEBUG, "PLUGIN: suppressed log message from plugin with unknown name");
      return;
    }

  if (flags & PLOG_ERR)
    msg_flags = M_INFO | M_NONFATAL;
  else if (flags & PLOG_WARN)
    msg_flags = M_INFO | M_WARN;
  else if (flags & PLOG_NOTE)
    msg_flags = M_INFO;
  else if (flags & PLOG_DEBUG)
    msg_flags = D_PLUGIN_DEBUG;

  if (flags & PLOG_ERRNO)
    msg_flags |= M_ERRNO;
  if (flags & PLOG_NOMUTE)
    msg_flags |= M_NOMUTE;

  if (MSG_TEST (msg_flags))
    {
      struct gc_arena gc;
      char* msg_fmt;

      /* Never add instance prefix; not thread safe */
      msg_flags |= M_NOIPREFIX;

      gc_init (&gc);
      msg_fmt = gc_malloc (ERR_BUF_SIZE, false, &gc);
      openvpn_snprintf (msg_fmt, ERR_BUF_SIZE, "PLUGIN %s: %s", name, format);
      x_msg_va (msg_flags, msg_fmt, arglist);

      gc_free (&gc);
    }
}

static void
plugin_log (openvpn_plugin_log_flags_t flags, const char *name, const char *format, ...)
{
  va_list arglist;
  va_start (arglist, format);
  plugin_vlog (flags, name, format, arglist);
  va_end (arglist);
}

static struct openvpn_plugin_callbacks callbacks = {
  plugin_log,
  plugin_vlog
};

static void
plugin_open_item (struct plugin *p,
		  const struct plugin_option *o,
		  struct openvpn_plugin_string_list **retlist,
		  const char **envp,
		  const int init_point)
{
  ASSERT (p->initialized);

  /* clear return list */
  if (retlist)
    *retlist = NULL;

  if (!p->plugin_handle && init_point == p->requested_initialization_point)
    {
      struct gc_arena gc = gc_new ();

      dmsg (D_PLUGIN_DEBUG, "PLUGIN_INIT: PRE");
      plugin_show_args_env (D_PLUGIN_DEBUG, o->argv, envp);

      /*
       * Call the plugin initialization
       */
      if (p->open3) {
        struct openvpn_plugin_args_open_in args = { p->plugin_type_mask,
                                                    (const char ** const) o->argv,
                                                    (const char ** const) envp,
                                                    &callbacks,
                                                    SSLAPI };
        struct openvpn_plugin_args_open_return retargs;

        CLEAR(retargs);
        retargs.return_list = retlist;
        if ((*p->open3)(OPENVPN_PLUGINv3_STRUCTVER, &args, &retargs) == OPENVPN_PLUGIN_FUNC_SUCCESS) {
          p->plugin_type_mask = retargs.type_mask;
          p->plugin_handle = retargs.handle;
        } else {
          p->plugin_handle = NULL;
        }
      } else if (p->open2)
	p->plugin_handle = (*p->open2)(&p->plugin_type_mask, o->argv, envp, retlist);
      else if (p->open1)
	p->plugin_handle = (*p->open1)(&p->plugin_type_mask, o->argv, envp);
      else
	ASSERT (0);

      msg (D_PLUGIN, "PLUGIN_INIT: POST %s '%s' intercepted=%s %s",
	   p->so_pathname,
	   print_argv (o->argv, &gc, PA_BRACKET),
	   plugin_mask_string (p->plugin_type_mask, &gc),
	   (retlist && *retlist) ? "[RETLIST]" : "");
      
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
}

static int
plugin_call_item (const struct plugin *p,
		  void *per_client_context,
		  const int type,
		  const struct argv *av,
		  struct openvpn_plugin_string_list **retlist,
		  const char **envp
#ifdef ENABLE_SSL
		  , int certdepth,
		  openvpn_x509_cert_t *current_cert
#endif
		 )
{
  int status = OPENVPN_PLUGIN_FUNC_SUCCESS;

  /* clear return list */
  if (retlist)
    *retlist = NULL;

  if (p->plugin_handle && (p->plugin_type_mask & OPENVPN_PLUGIN_MASK (type)))
    {
      struct gc_arena gc = gc_new ();
      struct argv a = argv_insert_head (av, p->so_pathname);

      dmsg (D_PLUGIN_DEBUG, "PLUGIN_CALL: PRE type=%s", plugin_type_name (type));
      plugin_show_args_env (D_PLUGIN_DEBUG, (const char **)a.argv, envp);

      /*
       * Call the plugin work function
       */
      if (p->func3) {
        struct openvpn_plugin_args_func_in args = { type,
                                                    (const char ** const) a.argv,
                                                    (const char ** const) envp,
                                                    p->plugin_handle,
                                                    per_client_context,
#ifdef ENABLE_SSL
						    (current_cert ? certdepth : -1),
						    current_cert
#else
						    -1,
						    NULL
#endif
	  };

        struct openvpn_plugin_args_func_return retargs;

        CLEAR(retargs);
        retargs.return_list = retlist;
        status = (*p->func3)(OPENVPN_PLUGINv3_STRUCTVER, &args, &retargs);
      } else if (p->func2)
	status = (*p->func2)(p->plugin_handle, type, (const char **)a.argv, envp, per_client_context, retlist);
      else if (p->func1)
	status = (*p->func1)(p->plugin_handle, type, (const char **)a.argv, envp);
      else
	ASSERT (0);

      msg (D_PLUGIN, "PLUGIN_CALL: POST %s/%s status=%d",
	   p->so_pathname,
	   plugin_type_name (type),
	   status);

      if (status == OPENVPN_PLUGIN_FUNC_ERROR)
	msg (M_WARN, "PLUGIN_CALL: plugin function %s failed with status %d: %s",
	     plugin_type_name (type),
	     status,
	     p->so_pathname);

      argv_reset (&a);
      gc_free (&gc);
    }
  return status;
}

static void
plugin_close_item (struct plugin *p)
{
  if (p->initialized)
    {
      msg (D_PLUGIN, "PLUGIN_CLOSE: %s", p->so_pathname);

      /*
       * Call the plugin close function
       */
      if (p->plugin_handle)
	(*p->close)(p->plugin_handle);

#ifndef WIN32
      if (dlclose (p->handle))
	msg (M_WARN, "PLUGIN_CLOSE: dlclose() failed on plugin: %s", p->so_pathname);
#elif defined(WIN32)
      if (!FreeLibrary (p->module))
	msg (M_WARN, "PLUGIN_CLOSE: FreeLibrary() failed on plugin: %s", p->so_pathname);
#endif

      p->initialized = false;
    }
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

static void
plugin_per_client_init (const struct plugin_common *pc,
			struct plugin_per_client *cli,
			const int init_point)
{
  const int n = pc->n;
  int i;

  for (i = 0; i < n; ++i)
    {
      const struct plugin *p = &pc->plugins[i];
      if (p->plugin_handle
	  && (init_point < 0 || init_point == p->requested_initialization_point)
	  && p->client_constructor)
	cli->per_client_context[i] = (*p->client_constructor)(p->plugin_handle);
    }
}

static void
plugin_per_client_destroy (const struct plugin_common *pc, struct plugin_per_client *cli)
{
  const int n = pc->n;
  int i;

  for (i = 0; i < n; ++i)
    {
      const struct plugin *p = &pc->plugins[i];
      void *cc = cli->per_client_context[i];

      if (p->client_destructor && cc)
	(*p->client_destructor)(p->plugin_handle, cc);
    }
  CLEAR (*cli);
}

struct plugin_list *
plugin_list_inherit (const struct plugin_list *src)
{
  struct plugin_list *pl;
  ALLOC_OBJ_CLEAR (pl, struct plugin_list);
  pl->common = src->common;
  ASSERT (pl->common);
  plugin_per_client_init (pl->common, &pl->per_client, -1);
  return pl;
}

static struct plugin_common *
plugin_common_init (const struct plugin_option_list *list)
{
  int i;
  struct plugin_common *pc;

  ALLOC_OBJ_CLEAR (pc, struct plugin_common);

  for (i = 0; i < list->n; ++i)
    {
      plugin_init_item (&pc->plugins[i],
			&list->plugins[i]);
      pc->n = i + 1;
    }

  static_plugin_common = pc;
  return pc;
}

static void
plugin_common_open (struct plugin_common *pc,
		    const struct plugin_option_list *list,
		    struct plugin_return *pr,
		    const struct env_set *es,
		    const int init_point)
{
  struct gc_arena gc = gc_new ();
  int i;
  const char **envp;

  envp = make_env_array (es, false, &gc);

  if (pr)
    plugin_return_init (pr);

  for (i = 0; i < pc->n; ++i)
    {
      plugin_open_item (&pc->plugins[i],
			&list->plugins[i],
			pr ? &pr->list[i] : NULL,
			envp,
			init_point);
    }

  if (pr)
    pr->n = i;

  gc_free (&gc);
}

static void
plugin_common_close (struct plugin_common *pc)
{
  static_plugin_common = NULL;
  if (pc)
    {
      int i;

      for (i = 0; i < pc->n; ++i)
	plugin_close_item (&pc->plugins[i]);
      free (pc);
    }
}

struct plugin_list *
plugin_list_init (const struct plugin_option_list *list)
{
  struct plugin_list *pl;
  ALLOC_OBJ_CLEAR (pl, struct plugin_list);
  pl->common = plugin_common_init (list);
  pl->common_owned = true;
  return pl;
}

void
plugin_list_open (struct plugin_list *pl,
		  const struct plugin_option_list *list,
		  struct plugin_return *pr,
		  const struct env_set *es,
		  const int init_point)
{
  plugin_common_open (pl->common, list, pr, es, init_point);
  plugin_per_client_init (pl->common, &pl->per_client, init_point);
}

int
plugin_call_ssl (const struct plugin_list *pl,
	     const int type,
	     const struct argv *av,
	     struct plugin_return *pr,
	     struct env_set *es
#ifdef ENABLE_SSL
             , int certdepth,
	     openvpn_x509_cert_t *current_cert
#endif
	    )
{
  if (pr)
    plugin_return_init (pr);

  if (plugin_defined (pl, type))
    {
      struct gc_arena gc = gc_new ();
      int i;
      const char **envp;
      const int n = plugin_n (pl);
      bool success = false;
      bool error = false;
      bool deferred = false;
      
      setenv_del (es, "script_type");
      envp = make_env_array (es, false, &gc);

      for (i = 0; i < n; ++i)
	{
	  const int status = plugin_call_item (&pl->common->plugins[i],
					       pl->per_client.per_client_context[i],
					       type,
					       av,
					       pr ? &pr->list[i] : NULL,
					       envp
#ifdef ENABLE_SSL
					       ,certdepth,
					       current_cert
#endif
					      );
	  switch (status)
	    {
	    case OPENVPN_PLUGIN_FUNC_SUCCESS:
	      success = true;
	      break;
	    case OPENVPN_PLUGIN_FUNC_DEFERRED:
	      deferred = true;
	      break;
	    default:
	      error = true;
	      break;
	    }
	}

      if (pr)
	pr->n = i;

      gc_free (&gc);

      if (type == OPENVPN_PLUGIN_ENABLE_PF && success)
	return OPENVPN_PLUGIN_FUNC_SUCCESS;
      else if (error)
	return OPENVPN_PLUGIN_FUNC_ERROR;
      else if (deferred)
	return OPENVPN_PLUGIN_FUNC_DEFERRED;
    }

  return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

void
plugin_list_close (struct plugin_list *pl)
{
  if (pl)
    {
      if (pl->common)
	{
	  plugin_per_client_destroy (pl->common, &pl->per_client);

	  if (pl->common_owned)
	    plugin_common_close (pl->common);
	}

      free (pl);
    }
}

void
plugin_abort (void)
{
  struct plugin_common *pc = static_plugin_common;
  static_plugin_common = NULL;
  if (pc)
    {
      int i;

      for (i = 0; i < pc->n; ++i)
	plugin_abort_item (&pc->plugins[i]);
    }
}

bool
plugin_defined (const struct plugin_list *pl, const int type)
{
  bool ret = false;

  if (pl)
    {
      const struct plugin_common *pc = pl->common;

      if (pc)
	{
	  int i;
	  const unsigned int mask = OPENVPN_PLUGIN_MASK (type);
	  for (i = 0; i < pc->n; ++i)
	    {
	      if (pc->plugins[i].plugin_type_mask & mask)
		{
		  ret = true;
		  break;
		}
	    }
	}
    }
  return ret;
}

/*
 * Plugin return functions
 */

static void
openvpn_plugin_string_list_item_free (struct openvpn_plugin_string_list *l)
{
  if (l)
    {
      free (l->name);
      string_clear (l->value);
      free (l->value);
      free (l);
    }
}

static void
openvpn_plugin_string_list_free (struct openvpn_plugin_string_list *l)
{
  struct openvpn_plugin_string_list *next;
  while (l)
    {
      next = l->next;
      openvpn_plugin_string_list_item_free (l);
      l = next;
    }
}

static struct openvpn_plugin_string_list *
openvpn_plugin_string_list_find (struct openvpn_plugin_string_list *l, const char *name)
{
  while (l)
    {
      if (!strcmp (l->name, name))
	return l;
      l = l->next;
    }
  return NULL;
}

void
plugin_return_get_column (const struct plugin_return *src,
			  struct plugin_return *dest,
			  const char *colname)
{
  int i;

  dest->n = 0;
  for (i = 0; i < src->n; ++i)
    dest->list[i] = openvpn_plugin_string_list_find (src->list[i], colname);
  dest->n = i;
}

void
plugin_return_free (struct plugin_return *pr)
{
  int i;
  for (i = 0; i < pr->n; ++i)
    openvpn_plugin_string_list_free (pr->list[i]);
  pr->n = 0;
}

#ifdef ENABLE_DEBUG
void
plugin_return_print (const int msglevel, const char *prefix, const struct plugin_return *pr)
{
  int i;
  msg (msglevel, "PLUGIN_RETURN_PRINT %s", prefix);
  for (i = 0; i < pr->n; ++i)
    {
      struct openvpn_plugin_string_list *l = pr->list[i];
      int count = 0;

      msg (msglevel, "PLUGIN #%d (%s)", i, prefix);
      while (l)
	{
	  msg (msglevel, "[%d] '%s' -> '%s'\n",
	       ++count,
	       l->name,
	       l->value);
	  l = l->next;
	}
    }
}
#endif

#else
static void dummy(void) {}
#endif /* ENABLE_PLUGIN */
