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
 * Support routines for adding/deleting network routes.
 */

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "common.h"
#include "error.h"
#include "route.h"
#include "misc.h"
#include "socket.h"
#include "manage.h"

#include "memdbg.h"

static void add_route (struct route *r, const struct tuntap *tt, unsigned int flags, const struct env_set *es);
static void delete_route (const struct route *r, const struct tuntap *tt, unsigned int flags, const struct env_set *es);
static bool get_default_gateway (in_addr_t *ret);

struct route_option_list *
new_route_option_list (struct gc_arena *a)
{
  struct route_option_list *ret;
  ALLOC_OBJ_CLEAR_GC (ret, struct route_option_list, a);
  return ret;
}

struct route_list *
new_route_list (struct gc_arena *a)
{
  struct route_list *ret;
  ALLOC_OBJ_CLEAR_GC (ret, struct route_list, a);
  return ret;
}

static const char *
route_string (const struct route *r, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (256, gc);
  buf_printf (&out, "ROUTE network %s netmask %s gateway %s",
	      print_in_addr_t (r->network, 0, gc),
	      print_in_addr_t (r->netmask, 0, gc),
	      print_in_addr_t (r->gateway, 0, gc)
	      );
  if (r->metric_defined)
    buf_printf (&out, " metric %d", r->metric);
  return BSTR (&out);
}

static bool
is_route_parm_defined (const char *parm)
{
  if (!parm)
    return false;
  if (!strcmp (parm, "default"))
    return false;
  return true;
}

static void
setenv_route_addr (struct env_set *es, const char *key, const in_addr_t addr, int i)
{
  struct gc_arena gc = gc_new ();
  struct buffer name = alloc_buf_gc (256, &gc);
  if (i >= 0)
    buf_printf (&name, "route_%s_%d", key, i);
  else
    buf_printf (&name, "route_%s", key);
  setenv_str (es, BSTR (&name), print_in_addr_t (addr, 0, &gc));
  gc_free (&gc);
}

static bool
get_special_addr (const struct route_special_addr *spec,
		  const char *string,
		  in_addr_t *out,
		  bool *status)
{
  *status = true;
  if (!strcmp (string, "vpn_gateway"))
    {
      if (spec->remote_endpoint_defined)
	*out = spec->remote_endpoint;
      else
	{
	  msg (M_INFO, PACKAGE_NAME " ROUTE: vpn_gateway undefined");
	  *status = false;
	}
      return true;
    }
  else if (!strcmp (string, "net_gateway"))
    {
      if (spec->net_gateway_defined)
	*out = spec->net_gateway;
      else
	{
	  msg (M_INFO, PACKAGE_NAME " ROUTE: net_gateway undefined -- unable to get default gateway from system");
	  *status = false;
	}
      return true;
    }
  else if (!strcmp (string, "remote_host"))
    {
      if (spec->remote_host_defined)
	*out = spec->remote_host;
      else
	{
	  msg (M_INFO, PACKAGE_NAME " ROUTE: remote_host undefined");
	  *status = false;
	}
      return true;
    }
  return false;
}

static bool
init_route (struct route *r,
	    const struct route_option *ro,
	    const struct route_special_addr *spec)
{
  const in_addr_t default_netmask = ~0;
  bool status;

  r->option = ro;
  r->defined = false;

  /* network */

  if (!is_route_parm_defined (ro->network))
    {
      goto fail;
    }
  
  if (!get_special_addr (spec, ro->network, &r->network, &status))
    {
      r->network = getaddr (
			    GETADDR_RESOLVE
			    | GETADDR_HOST_ORDER
			    | GETADDR_WARN_ON_SIGNAL,
			    ro->network,
			    0,
			    &status,
			    NULL);
    }

  if (!status)
    goto fail;

  /* netmask */

  if (is_route_parm_defined (ro->netmask))
    {
      r->netmask = getaddr (
			    GETADDR_HOST_ORDER
			    | GETADDR_WARN_ON_SIGNAL,
			    ro->netmask,
			    0,
			    &status,
			    NULL);
      if (!status)
	goto fail;
    }
  else
    r->netmask = default_netmask;

  /* gateway */

  if (is_route_parm_defined (ro->gateway))
    {
      if (!get_special_addr (spec, ro->gateway, &r->gateway, &status))
	{
	  r->gateway = getaddr (
				GETADDR_RESOLVE
				| GETADDR_HOST_ORDER
				| GETADDR_WARN_ON_SIGNAL,
				ro->gateway,
				0,
				&status,
				NULL);
	}
      if (!status)
	goto fail;
    }
  else
    {
      if (spec->remote_endpoint_defined)
	r->gateway = spec->remote_endpoint;
      else
	{
	  msg (M_WARN, PACKAGE_NAME " ROUTE: " PACKAGE_NAME " needs a gateway parameter for a --route option and no default was specified by either --route-gateway or --ifconfig options");
	  goto fail;
	}
    }

  /* metric */

  r->metric_defined = false;
  r->metric = 0;
  if (is_route_parm_defined (ro->metric))
    {
      r->metric = atoi (ro->metric);
      if (r->metric < 0)
	{
	  msg (M_WARN, PACKAGE_NAME " ROUTE: route metric for network %s (%s) must be >= 0",
	       ro->network,
	       ro->metric);
	  goto fail;
	}
      r->metric_defined = true;
    }
  else
    {
      r->metric = 0;
      r->metric_defined = false;
    }

  r->defined = true;

  return true;

 fail:
  msg (M_WARN, PACKAGE_NAME " ROUTE: failed to parse/resolve route for host/network: %s",
       ro->network);
  r->defined = false;
  return false;
}

void
add_route_to_option_list (struct route_option_list *l,
			  const char *network,
			  const char *netmask,
			  const char *gateway,
			  const char *metric)
{
  struct route_option *ro;
  if (l->n >= MAX_ROUTES)
    msg (M_FATAL, PACKAGE_NAME " ROUTE: cannot add more than %d routes",
	 MAX_ROUTES);
  ro = &l->routes[l->n];
  ro->network = network;
  ro->netmask = netmask;
  ro->gateway = gateway;
  ro->metric = metric;
  ++l->n;
}

void
clear_route_list (struct route_list *rl)
{
  CLEAR (*rl);
}

bool
init_route_list (struct route_list *rl,
		 const struct route_option_list *opt,
		 const char *remote_endpoint,
		 in_addr_t remote_host,
		 struct env_set *es)
{
  bool ret = true;

  clear_route_list (rl);

  if (remote_host)
    {
      rl->spec.remote_host = remote_host;
      rl->spec.remote_host_defined = true;
    }

  rl->spec.net_gateway_defined = get_default_gateway (&rl->spec.net_gateway);
  if (rl->spec.net_gateway_defined)
    {
      setenv_route_addr (es, "net_gateway", rl->spec.net_gateway, -1);
    }
  rl->redirect_default_gateway = opt->redirect_default_gateway;
  rl->redirect_local = opt->redirect_local;
  rl->redirect_def1 = opt->redirect_def1;

  if (is_route_parm_defined (remote_endpoint))
    {
      rl->spec.remote_endpoint = getaddr (
				     GETADDR_RESOLVE
				     | GETADDR_HOST_ORDER
				     | GETADDR_WARN_ON_SIGNAL,
				     remote_endpoint,
				     0,
				     &rl->spec.remote_endpoint_defined,
				     NULL);

      if (rl->spec.remote_endpoint_defined)
	{
	  setenv_route_addr (es, "vpn_gateway", rl->spec.remote_endpoint, -1);
	}
      else
	{
	  msg (M_WARN, PACKAGE_NAME " ROUTE: failed to parse/resolve default gateway: %s",
	       remote_endpoint);
	  ret = false;
	}
    }
  else
    rl->spec.remote_endpoint_defined = false;

  ASSERT (opt->n >= 0 && opt->n < MAX_ROUTES);

  /* parse the routes from opt to rl */
  {
    int i, j = 0;
    for (i = 0; i < opt->n; ++i)
      {
	if (!init_route (&rl->routes[j],
			 &opt->routes[i],
			 &rl->spec))
	  ret = false;
	else
	  ++j;
      }
    rl->n = j;
  }

  return ret;
}

static void
add_route3 (in_addr_t network,
	    in_addr_t netmask,
	    in_addr_t gateway,
	    const struct tuntap *tt,
	    unsigned int flags,
	    const struct env_set *es)
{
  struct route r;
  CLEAR (r);
  r.defined = true;
  r.network = network;
  r.netmask = netmask;
  r.gateway = gateway;
  add_route (&r, tt, flags, es);
}

static void
del_route3 (in_addr_t network,
	    in_addr_t netmask,
	    in_addr_t gateway,
	    const struct tuntap *tt,
	    unsigned int flags,
	    const struct env_set *es)
{
  struct route r;
  CLEAR (r);
  r.defined = true;
  r.network = network;
  r.netmask = netmask;
  r.gateway = gateway;
  delete_route (&r, tt, flags, es);
}

static void
redirect_default_route_to_vpn (struct route_list *rl, const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
  const char err[] = "NOTE: unable to redirect default gateway --";

  if (rl->redirect_default_gateway)
    {
      if (!rl->spec.remote_endpoint_defined)
	{
	  msg (M_WARN, "%s VPN gateway parameter (--route-gateway or --ifconfig) is missing", err);
	}
      else if (!rl->spec.net_gateway_defined)
	{
	  msg (M_WARN, "%s Cannot read current default gateway from system", err);
	}
      else if (!rl->spec.remote_host_defined)
	{
	  msg (M_WARN, "%s Cannot obtain current remote host address", err);
	}
      else
	{
	  /* route remote host to original default gateway */
	  if (!rl->redirect_local)
	    add_route3 (rl->spec.remote_host,
			~0,
			rl->spec.net_gateway,
			tt,
			flags,
			es);

	  if (rl->redirect_def1)
	    {
	      /* add new default route (1st component) */
	      add_route3 (0x00000000,
			  0x80000000,
			  rl->spec.remote_endpoint,
			  tt,
			  flags,
			  es);

	      /* add new default route (2nd component) */
	      add_route3 (0x80000000,
			  0x80000000,
			  rl->spec.remote_endpoint,
			  tt,
			  flags,
			  es);
	    }
	  else
	    {
	      /* delete default route */
	      del_route3 (0,
			  0,
			  rl->spec.net_gateway,
			  tt,
			  flags,
			  es);

	      /* add new default route */
	      add_route3 (0,
			  0,
			  rl->spec.remote_endpoint,
			  tt,
			  flags,
			  es);
	    }

	  /* set a flag so we can undo later */
	  rl->did_redirect_default_gateway = true;
	}
    }
}

static void
undo_redirect_default_route_to_vpn (struct route_list *rl, const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
  if (rl->did_redirect_default_gateway)
    {
      /* delete remote host route */
      if (!rl->redirect_local)
	del_route3 (rl->spec.remote_host,
		    ~0,
		    rl->spec.net_gateway,
		    tt,
		    flags,
		    es);

      if (rl->redirect_def1)
	{
	  /* delete default route (1st component) */
	  del_route3 (0x00000000,
		      0x80000000,
		      rl->spec.remote_endpoint,
		      tt,
		      flags,
		      es);

	  /* delete default route (2nd component) */
	  del_route3 (0x80000000,
		      0x80000000,
		      rl->spec.remote_endpoint,
		      tt,
		      flags,
		      es);
	}
      else
	{
	  /* delete default route */
	  del_route3 (0,
		      0,
		      rl->spec.remote_endpoint,
		      tt,
		      flags,
		      es);

	  /* restore original default route */
	  add_route3 (0,
		      0,
		      rl->spec.net_gateway,
		      tt,
		      flags,
		      es);
	}

      rl->did_redirect_default_gateway = false;
    }
}

void
add_routes (struct route_list *rl, const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
  redirect_default_route_to_vpn (rl, tt, flags, es);
  if (!rl->routes_added)
    {
      int i;

#ifdef ENABLE_MANAGEMENT
      if (management && rl->n)
	{
	  management_set_state (management,
				OPENVPN_STATE_ADD_ROUTES,
				NULL,
				0);
	}
#endif
      
      for (i = 0; i < rl->n; ++i)
	{
	  if (flags & ROUTE_DELETE_FIRST)
	    delete_route (&rl->routes[i], tt, flags, es);
	  add_route (&rl->routes[i], tt, flags, es);
	}
      rl->routes_added = true;
    }
}

void
delete_routes (struct route_list *rl, const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
  if (rl->routes_added)
    {
      int i;
      for (i = rl->n - 1; i >= 0; --i)
	{
	  const struct route *r = &rl->routes[i];
	  delete_route (r, tt, flags, es);
	}
      rl->routes_added = false;
    }
  undo_redirect_default_route_to_vpn (rl, tt, flags, es);

  CLEAR (*rl);
}

#ifdef ENABLE_DEBUG

static const char *
show_opt (const char *option)
{
  if (!option)
    return "nil";
  else
    return option;
}

static void
print_route_option (const struct route_option *ro, int level)
{
  msg (level, "  route %s/%s/%s/%s",
       show_opt (ro->network),
       show_opt (ro->netmask),
       show_opt (ro->gateway),
       show_opt (ro->metric));
}

void
print_route_options (const struct route_option_list *rol,
		     int level)
{
  int i;
  if (rol->redirect_default_gateway)
    msg (level, "  [redirect_default_gateway local=%d]",
	 rol->redirect_local);
  for (i = 0; i < rol->n; ++i)
    print_route_option (&rol->routes[i], level);
}

#endif

static void
print_route (const struct route *r, int level)
{
  struct gc_arena gc = gc_new ();
  if (r->defined)
    msg (level, "%s", route_string (r, &gc));
  gc_free (&gc);
}

void
print_routes (const struct route_list *rl, int level)
{
  int i;
  for (i = 0; i < rl->n; ++i)
    print_route (&rl->routes[i], level);
}

static void
setenv_route (struct env_set *es, const struct route *r, int i)
{
  struct gc_arena gc = gc_new ();
  if (r->defined)
    {
      setenv_route_addr (es, "network", r->network, i);
      setenv_route_addr (es, "netmask", r->netmask, i);
      setenv_route_addr (es, "gateway", r->gateway, i);

      if (r->metric_defined)
	{
	  struct buffer name = alloc_buf_gc (256, &gc);
	  buf_printf (&name, "route_metric_%d", i);
	  setenv_int (es, BSTR (&name), r->metric);
	}
    }
  gc_free (&gc);
}

void
setenv_routes (struct env_set *es, const struct route_list *rl)
{
  int i;
  for (i = 0; i < rl->n; ++i)
    setenv_route (es, &rl->routes[i], i + 1);
}

static void
add_route (struct route *r, const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
  struct gc_arena gc;
  struct buffer buf;
  const char *network;
  const char *netmask;
  const char *gateway;
  bool status = false;

  if (!r->defined)
    return;

  gc_init (&gc);
  buf = alloc_buf_gc (256, &gc);

  network = print_in_addr_t (r->network, 0, &gc);
  netmask = print_in_addr_t (r->netmask, 0, &gc);
  gateway = print_in_addr_t (r->gateway, 0, &gc);

  /*
   * Filter out routes which are essentially no-ops
   */
  if (r->network == r->gateway && r->netmask == 0xFFFFFFFF)
    {
      msg (M_INFO, PACKAGE_NAME " ROUTE: omitted no-op route: %s/%s -> %s",
	   network, netmask, gateway);
      goto done;
    }

#if defined(TARGET_LINUX)
#ifdef CONFIG_FEATURE_IPROUTE
  buf_printf (&buf, IPROUTE_PATH " route add %s/%d via %s",
	      network,
	      count_netmask_bits(netmask),
	      gateway);
  if (r->metric_defined)
    buf_printf (&buf, " metric %d", r->metric);

#else
  buf_printf (&buf, ROUTE_PATH " add -net %s netmask %s gw %s",
	      network,
	      netmask,
	      gateway);
  if (r->metric_defined)
    buf_printf (&buf, " metric %d", r->metric);
#endif  /*CONFIG_FEATURE_IPROUTE*/
  msg (D_ROUTE, "%s", BSTR (&buf));
  status = system_check (BSTR (&buf), es, 0, "ERROR: Linux route add command failed");

#elif defined (WIN32)

  buf_printf (&buf, ROUTE_PATH " ADD %s MASK %s %s",
	      network,
	      netmask,
	      gateway);
  if (r->metric_defined)
    buf_printf (&buf, " METRIC %d", r->metric);

  msg (D_ROUTE, "%s", BSTR (&buf));

  if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_IPAPI)
    {
      status = add_route_ipapi (r, tt);
      msg (D_ROUTE, "Route addition via IPAPI %s", status ? "succeeded" : "failed");
    }
  else if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_EXE)
    {
      netcmd_semaphore_lock ();
      status = system_check (BSTR (&buf), es, 0, "ERROR: Windows route add command failed");
      netcmd_semaphore_release ();
    }
  else
    {
      ASSERT (0);
    }

#elif defined (TARGET_SOLARIS)

  /* example: route add 192.0.2.32 -netmask 255.255.255.224 somegateway */

  buf_printf (&buf, ROUTE_PATH " add");

#if 0
  if (r->metric_defined)
    buf_printf (&buf, " -rtt %d", r->metric);
#endif

  buf_printf (&buf, " %s -netmask %s %s",
	      network,
	      netmask,
	      gateway);

  msg (D_ROUTE, "%s", BSTR (&buf));
  status = system_check (BSTR (&buf), es, 0, "ERROR: Solaris route add command failed");

#elif defined(TARGET_FREEBSD)

  buf_printf (&buf, ROUTE_PATH " add");

#if 0
  if (r->metric_defined)
    buf_printf (&buf, " -rtt %d", r->metric);
#endif

  buf_printf (&buf, " -net %s %s %s",
	      network,
	      gateway,
	      netmask);

  msg (D_ROUTE, "%s", BSTR (&buf));
  status = system_check (BSTR (&buf), es, 0, "ERROR: FreeBSD route add command failed");

#elif defined(TARGET_DARWIN)

  buf_printf (&buf, ROUTE_PATH " add");

#if 0
  if (r->metric_defined)
    buf_printf (&buf, " -rtt %d", r->metric);
#endif

  buf_printf (&buf, " -net %s %s %s",
              network,
              gateway,
              netmask);

  msg (D_ROUTE, "%s", BSTR (&buf));
  status = system_check (BSTR (&buf), es, 0, "ERROR: OS X route add command failed");

#elif defined(TARGET_OPENBSD) || defined(TARGET_NETBSD)

  buf_printf (&buf, ROUTE_PATH " add");

#if 0
  if (r->metric_defined)
    buf_printf (&buf, " -rtt %d", r->metric);
#endif

  buf_printf (&buf, " -net %s %s -netmask %s",
	      network,
	      gateway,
	      netmask);

  msg (D_ROUTE, "%s", BSTR (&buf));
  status = system_check (BSTR (&buf), es, 0, "ERROR: OpenBSD/NetBSD route add command failed");

#else
  msg (M_FATAL, "Sorry, but I don't know how to do 'route' commands on this operating system.  Try putting your routes in a --route-up script");
#endif

 done:
  r->defined = status;
  gc_free (&gc);
}

static void
delete_route (const struct route *r, const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
  struct gc_arena gc;
  struct buffer buf;
  const char *network;
  const char *netmask;
  const char *gateway;

  if (!r->defined)
    return;

  gc_init (&gc);

  buf = alloc_buf_gc (256, &gc);
  network = print_in_addr_t (r->network, 0, &gc);
  netmask = print_in_addr_t (r->netmask, 0, &gc);
  gateway = print_in_addr_t (r->gateway, 0, &gc);

#if defined(TARGET_LINUX)
#ifdef CONFIG_FEATURE_IPROUTE
  buf_printf (&buf, IPROUTE_PATH " route del %s/%d",
	      network,
	      count_netmask_bits(netmask));
#else

  buf_printf (&buf, ROUTE_PATH " del -net %s netmask %s",
	      network,
	      netmask);
#endif /*CONFIG_FEATURE_IPROUTE*/
  msg (D_ROUTE, "%s", BSTR (&buf));
  system_check (BSTR (&buf), es, 0, "ERROR: Linux route delete command failed");

#elif defined (WIN32)
  
  buf_printf (&buf, ROUTE_PATH " DELETE %s MASK %s %s",
	      network,
              netmask,
              gateway);

  msg (D_ROUTE, "%s", BSTR (&buf));

  if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_IPAPI)
    {
      const bool status = del_route_ipapi (r, tt);
      msg (D_ROUTE, "Route deletion via IPAPI %s", status ? "succeeded" : "failed");
    }
  else if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_EXE)
    {
      netcmd_semaphore_lock ();
      system_check (BSTR (&buf), es, 0, "ERROR: Windows route delete command failed");
      netcmd_semaphore_release ();
    }
  else
    {
      ASSERT (0);
    }

#elif defined (TARGET_SOLARIS)

  buf_printf (&buf, ROUTE_PATH " delete %s -netmask %s %s",
	      network,
	      netmask,
	      gateway);

  msg (D_ROUTE, "%s", BSTR (&buf));
  system_check (BSTR (&buf), es, 0, "ERROR: Solaris route delete command failed");

#elif defined(TARGET_FREEBSD)

  buf_printf (&buf, ROUTE_PATH " delete -net %s %s %s",
	      network,
	      gateway,
	      netmask);

  msg (D_ROUTE, "%s", BSTR (&buf));
  system_check (BSTR (&buf), es, 0, "ERROR: FreeBSD route delete command failed");

#elif defined(TARGET_DARWIN)

  buf_printf (&buf, ROUTE_PATH " delete -net %s %s %s",
              network,
              gateway,
              netmask);

  msg (D_ROUTE, "%s", BSTR (&buf));
  system_check (BSTR (&buf), es, 0, "ERROR: OS X route delete command failed");

#elif defined(TARGET_OPENBSD) || defined(TARGET_NETBSD)

  buf_printf (&buf, ROUTE_PATH " delete -net %s %s -netmask %s",
	      network,
	      gateway,
	      netmask);

  msg (D_ROUTE, "%s", BSTR (&buf));
  system_check (BSTR (&buf), es, 0, "ERROR: OpenBSD/NetBSD route delete command failed");

#else
  msg (M_FATAL, "Sorry, but I don't know how to do 'route' commands on this operating system.  Try putting your routes in a --route-up script");
#endif

  gc_free (&gc);
}

/*
 * The --redirect-gateway option requires OS-specific code below
 * to get the current default gateway.
 */

#if defined(WIN32)

static const MIB_IPFORWARDTABLE *
get_windows_routing_table (struct gc_arena *gc)
{
  ULONG size = 0;
  PMIB_IPFORWARDTABLE rt = NULL;
  DWORD status;

  status = GetIpForwardTable (NULL, &size, TRUE);
  if (status == ERROR_INSUFFICIENT_BUFFER)
    {
      rt = (PMIB_IPFORWARDTABLE) gc_malloc (size, false, gc);
      status = GetIpForwardTable (rt, &size, TRUE);
      if (status != NO_ERROR)
	{
	  msg (D_ROUTE, "NOTE: GetIpForwardTable returned error: %s (code=%u)",
	       strerror_win32 (status, gc),
	       (unsigned int)status);
	  rt = NULL;
	}
    }
  return rt;
}

static int
test_route (const IP_ADAPTER_INFO *adapters,
	    const in_addr_t gateway,
	    DWORD *index)
{
  int count = 0;
  DWORD i = adapter_index_of_ip (adapters, gateway, &count);
  if (index)
    *index = i;
  return count;
}

static void
test_route_helper (bool *ret,
		   int *count,
		   int *good,
		   int *ambig,
		   const IP_ADAPTER_INFO *adapters,
		   const in_addr_t gateway)
{
  int c;

  ++*count;
  c = test_route (adapters, gateway, NULL);
  if (c == 0)
    *ret = false;
  else
    ++*good;
  if (c > 1)
    ++*ambig;
}

/*
 * If we tried to add routes now, would we succeed?
 */
bool
test_routes (const struct route_list *rl, const struct tuntap *tt)
{
  struct gc_arena gc = gc_new ();
  const IP_ADAPTER_INFO *adapters = get_adapter_info_list (&gc);
  bool ret = false;
  int count = 0;
  int good = 0;
  int ambig = 0;
  bool adapter_up = false;

  if (is_adapter_up (tt, adapters))
    {
      ret = true;
      adapter_up = true;

      if (rl)
	{
	  int i;
	  for (i = 0; i < rl->n; ++i)
	    test_route_helper (&ret, &count, &good, &ambig, adapters, rl->routes[i].gateway);

	  if (rl->redirect_default_gateway && rl->spec.remote_endpoint_defined)
	    test_route_helper (&ret, &count, &good, &ambig, adapters, rl->spec.remote_endpoint);
	}
    }

  msg (D_ROUTE, "TEST ROUTES: %d/%d succeeded len=%d ret=%d a=%d u/d=%s",
       good,
       count,
       rl ? rl->n : -1,
       (int)ret,
       ambig,
       adapter_up ? "up" : "down");

  gc_free (&gc);
  return ret;
}

static bool
get_default_gateway (in_addr_t *ret)
{
  struct gc_arena gc = gc_new ();
  bool ret_bool = false;
  int i;
  const MIB_IPFORWARDTABLE *routes = get_windows_routing_table (&gc);

  if (!routes)
    goto done;

  for (i = 0; i < routes->dwNumEntries; ++i)
    {
      const MIB_IPFORWARDROW *row = &routes->table[i];
      const in_addr_t net = ntohl (row->dwForwardDest);
      const in_addr_t mask = ntohl (row->dwForwardMask);
      const in_addr_t gw = ntohl (row->dwForwardNextHop);

#if 0
      msg (M_INFO, "route[%d] %s %s %s",
	   i,
	   print_in_addr_t ((in_addr_t) net, 0, &gc),
	   print_in_addr_t ((in_addr_t) mask, 0, &gc),
	   print_in_addr_t ((in_addr_t) gw, 0, &gc));
#endif
      if (!net && !mask)
	{
	  *ret = gw;
	  ret_bool = true;
	  break;
	}
    }
  
 done:
  gc_free (&gc);
  return ret_bool;
}

static DWORD
windows_route_find_if_index (const struct route *r, const struct tuntap *tt)
{
  struct gc_arena gc = gc_new ();
  DWORD ret = ~0;
  int count = 0;
  const IP_ADAPTER_INFO *adapters = get_adapter_info_list (&gc);
  const IP_ADAPTER_INFO *tun_adapter = get_tun_adapter (tt, adapters);
  bool on_tun = false;

  /* first test on tun interface */
  if (is_ip_in_adapter_subnet (tun_adapter, r->gateway, NULL))
    {
      ret = tun_adapter->Index;
      count = 1;
      on_tun = true;
    }
  else /* test on other interfaces */
    {
      count = test_route (adapters, r->gateway, &ret);
    }

  if (count == 0)
    {
      msg (M_WARN, "Warning: route gateway is not reachable on any active network adapters: %s",
	   print_in_addr_t (r->gateway, 0, &gc));
      ret = ~0;
    }
  else if (count > 1)
    {
      msg (M_WARN, "Warning: route gateway is ambiguous: %s (%d matches)",
	   print_in_addr_t (r->gateway, 0, &gc),
	   count);
      ret = ~0;
    }

  dmsg (D_ROUTE_DEBUG, "DEBUG: route find if: on_tun=%d count=%d index=%d",
       on_tun,
       count,
       (int)ret);

  gc_free (&gc);
  return ret;
}

bool
add_route_ipapi (const struct route *r, const struct tuntap *tt)
{
  struct gc_arena gc = gc_new ();
  bool ret = false;
  DWORD status;
  const DWORD if_index = windows_route_find_if_index (r, tt);  

  if (if_index != ~0)
    {
      MIB_IPFORWARDROW fr;
      CLEAR (fr);
      fr.dwForwardDest = htonl (r->network);
      fr.dwForwardMask = htonl (r->netmask);
      fr.dwForwardPolicy = 0;
      fr.dwForwardNextHop = htonl (r->gateway);
      fr.dwForwardIfIndex = if_index;
      fr.dwForwardType = 4;  /* the next hop is not the final dest */
      fr.dwForwardProto = 3; /* PROTO_IP_NETMGMT */
      fr.dwForwardAge = 0;
      fr.dwForwardNextHopAS = 0;
      fr.dwForwardMetric1 = r->metric_defined ? r->metric : 1;
      fr.dwForwardMetric2 = ~0;
      fr.dwForwardMetric3 = ~0;
      fr.dwForwardMetric4 = ~0;
      fr.dwForwardMetric5 = ~0;

      if ((r->network & r->netmask) != r->network)
	msg (M_WARN, "Warning: address %s is not a network address in relation to netmask %s",
	     print_in_addr_t (r->network, 0, &gc),
	     print_in_addr_t (r->netmask, 0, &gc));

      status = CreateIpForwardEntry (&fr);

      if (status == NO_ERROR)
	ret = true;
      else
	{
	  /* failed, try a different forward type (--redirect-gateway over RRAS seems to need this) */
	  fr.dwForwardType = 3;  /* the next hop is the final dest */

	  status = CreateIpForwardEntry (&fr);

	  if (status == NO_ERROR)
	    ret = true;
	  else
	    msg (M_WARN, "ROUTE: route addition failed using CreateIpForwardEntry: %s [if_index=%u]",
		 strerror_win32 (status, &gc),
		 (unsigned int)if_index);
	}
    }

  gc_free (&gc);
  return ret;
}

bool
del_route_ipapi (const struct route *r, const struct tuntap *tt)
{
  struct gc_arena gc = gc_new ();
  bool ret = false;
  DWORD status;
  const DWORD if_index = windows_route_find_if_index (r, tt);

  if (if_index != ~0)
    {
      MIB_IPFORWARDROW fr;
      CLEAR (fr);

      fr.dwForwardDest = htonl (r->network);
      fr.dwForwardMask = htonl (r->netmask);
      fr.dwForwardPolicy = 0;
      fr.dwForwardNextHop = htonl (r->gateway);
      fr.dwForwardIfIndex = if_index;

      status = DeleteIpForwardEntry (&fr);

      if (status == NO_ERROR)
	ret = true;
      else
	msg (M_WARN, "ROUTE: route deletion failed using DeleteIpForwardEntry: %s",
	     strerror_win32 (status, &gc));
    }

  gc_free (&gc);
  return ret;
}

static const char *
format_route_entry (const MIB_IPFORWARDROW *r, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (256, gc);
  buf_printf (&out, "%s %s %s p=%d i=%d t=%d pr=%d a=%d h=%d m=%d/%d/%d/%d/%d", 
	      print_in_addr_t (r->dwForwardDest, IA_NET_ORDER, gc),
	      print_in_addr_t (r->dwForwardMask, IA_NET_ORDER, gc),
	      print_in_addr_t (r->dwForwardNextHop, IA_NET_ORDER, gc),
	      (int)r->dwForwardPolicy,
	      (int)r->dwForwardIfIndex,
	      (int)r->dwForwardType,
	      (int)r->dwForwardProto,
	      (int)r->dwForwardAge,
	      (int)r->dwForwardNextHopAS,
	      (int)r->dwForwardMetric1,
	      (int)r->dwForwardMetric2,
	      (int)r->dwForwardMetric3,
	      (int)r->dwForwardMetric4,
	      (int)r->dwForwardMetric5);
  return BSTR (&out);
}

/*
 * Show current routing table
 */
void
show_routes (int msglev)
{
  struct gc_arena gc = gc_new ();
  int i;

  const MIB_IPFORWARDTABLE *rt = get_windows_routing_table (&gc);

  msg (msglev, "SYSTEM ROUTING TABLE");
  if (rt)
    {
      for (i = 0; i < rt->dwNumEntries; ++i)
	{
	  msg (msglev, "%s", format_route_entry (&rt->table[i], &gc));
	}
    }
  gc_free (&gc);
}

#elif defined(TARGET_LINUX)

static bool
get_default_gateway (in_addr_t *ret)
{
  struct gc_arena gc = gc_new ();
  FILE *fp = fopen ("/proc/net/route", "r");
  if (fp)
    {
      char line[256];
      int count = 0;
      while (fgets (line, sizeof (line), fp) != NULL)
	{
	  if (count)
	    {
	      unsigned int net_x = 0;
	      unsigned int mask_x = 0;
	      unsigned int gw_x = 0;
	      const int np = sscanf (line, "%*s\t%x\t%x\t%*s\t%*s\t%*s\t%*s\t%x",
				     &net_x,
				     &gw_x,
				     &mask_x);
	      if (np == 3)
		{
		  const in_addr_t net = ntohl (net_x);
		  const in_addr_t mask = ntohl (mask_x);
		  const in_addr_t gw = ntohl (gw_x);
#if 0
		  msg (M_INFO, "route %s %s %s",
		       print_in_addr_t ((in_addr_t) net, 0, &gc),
		       print_in_addr_t ((in_addr_t) mask, 0, &gc),
		       print_in_addr_t ((in_addr_t) gw, 0, &gc));
#endif
		  if (!net && !mask)
		    {
		      fclose (fp);
		      *ret = gw;
		      gc_free (&gc);
		      return true;
		    }
		}
	    }
	  ++count;
	}
      fclose (fp);
    }

  gc_free (&gc);
  return false;
}

#elif defined(TARGET_FREEBSD)

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* all of this is taken from <net/route.h> in FreeBSD */
#define RTA_DST     0x1
#define RTA_GATEWAY 0x2
#define RTA_NETMASK 0x4

#define RTM_GET     0x4
#define RTM_VERSION 5

#define RTF_UP      0x1
#define RTF_GATEWAY 0x2

/*
 * These numbers are used by reliable protocols for determining
 * retransmission behavior and are included in the routing structure.
 */
struct rt_metrics {
        u_long  rmx_locks;      /* Kernel must leave these values alone */
        u_long  rmx_mtu;        /* MTU for this path */
        u_long  rmx_hopcount;   /* max hops expected */
        u_long  rmx_expire;     /* lifetime for route, e.g. redirect */
        u_long  rmx_recvpipe;   /* inbound delay-bandwidth product */
        u_long  rmx_sendpipe;   /* outbound delay-bandwidth product */
        u_long  rmx_ssthresh;   /* outbound gateway buffer limit */
        u_long  rmx_rtt;        /* estimated round trip time */
        u_long  rmx_rttvar;     /* estimated rtt variance */
        u_long  rmx_pksent;     /* packets sent using this route */
        u_long  rmx_filler[4];  /* will be used for T/TCP later */
};

/*
 * Structures for routing messages.
 */
struct rt_msghdr {
        u_short rtm_msglen;     /* to skip over non-understood messages */
        u_char  rtm_version;    /* future binary compatibility */
        u_char  rtm_type;       /* message type */
        u_short rtm_index;      /* index for associated ifp */
        int     rtm_flags;      /* flags, incl. kern & message, e.g. DONE */
        int     rtm_addrs;      /* bitmask identifying sockaddrs in msg */
        pid_t   rtm_pid;        /* identify sender */
        int     rtm_seq;        /* for sender to identify action */
        int     rtm_errno;      /* why failed */
        int     rtm_use;        /* from rtentry */
        u_long  rtm_inits;      /* which metrics we are initializing */
        struct  rt_metrics rtm_rmx; /* metrics themselves */
};

struct {
  struct rt_msghdr m_rtm;
  char       m_space[512];
} m_rtmsg;

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

static bool
get_default_gateway (in_addr_t *ret)
{
  struct gc_arena gc = gc_new ();
  int s, seq, l, pid, rtm_addrs, i;
  struct sockaddr so_dst, so_mask;
  char *cp = m_rtmsg.m_space; 
  struct sockaddr *gate = NULL, *sa;
  struct  rt_msghdr *rtm_aux;

#define NEXTADDR(w, u) \
        if (rtm_addrs & (w)) {\
            l = ROUNDUP(u.sa_len); memmove(cp, &(u), l); cp += l;\
        }

#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

#define rtm m_rtmsg.m_rtm

  pid = getpid();
  seq = 0;
  rtm_addrs = RTA_DST | RTA_NETMASK;

  bzero(&so_dst, sizeof(so_dst));
  bzero(&so_mask, sizeof(so_mask));
  bzero(&rtm, sizeof(struct rt_msghdr));

  rtm.rtm_type = RTM_GET;
  rtm.rtm_flags = RTF_UP | RTF_GATEWAY;
  rtm.rtm_version = RTM_VERSION;
  rtm.rtm_seq = ++seq;
  rtm.rtm_addrs = rtm_addrs; 

  so_dst.sa_family = AF_INET;
  so_dst.sa_len = sizeof(struct sockaddr_in);
  so_mask.sa_family = AF_INET;
  so_mask.sa_len = sizeof(struct sockaddr_in);

  NEXTADDR(RTA_DST, so_dst);
  NEXTADDR(RTA_NETMASK, so_mask);

  rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;

  s = socket(PF_ROUTE, SOCK_RAW, 0);

  if (write(s, (char *)&m_rtmsg, l) < 0)
    {
      warn("writing to routing socket");
      gc_free (&gc);
      close(s);
      return false;
    }

  do {
    l = read(s, (char *)&m_rtmsg, sizeof(m_rtmsg));
  } while (l > 0 && (rtm.rtm_seq != seq || rtm.rtm_pid != pid));
                        
  close(s);

  rtm_aux = &rtm;

  cp = ((char *)(rtm_aux + 1));
  if (rtm_aux->rtm_addrs) {
    for (i = 1; i; i <<= 1)
      if (i & rtm_aux->rtm_addrs) {
	sa = (struct sockaddr *)cp;
	if (i == RTA_GATEWAY )
	  gate = sa;
	ADVANCE(cp, sa);
      }
  }
  else
    {
      gc_free (&gc);
      return false;
    }


  if (gate != NULL )
    {
      *ret = ntohl(((struct sockaddr_in *)gate)->sin_addr.s_addr);
#if 1
      msg (M_INFO, "gw %s",
	   print_in_addr_t ((in_addr_t) *ret, 0, &gc));
#endif

      gc_free (&gc);
      return true;
    }
  else
    {
      gc_free (&gc);
      return false;
    }
}

#elif defined(TARGET_DARWIN)

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* all of this is taken from <net/route.h> in Darwin */
#define RTA_DST     0x1
#define RTA_GATEWAY 0x2
#define RTA_NETMASK 0x4

#define RTM_GET     0x4
#define RTM_VERSION 5

#define RTF_UP      0x1
#define RTF_GATEWAY 0x2

/*
 * These numbers are used by reliable protocols for determining
 * retransmission behavior and are included in the routing structure.
 */
struct rt_metrics {
        u_long  rmx_locks;      /* Kernel must leave these values alone */
        u_long  rmx_mtu;        /* MTU for this path */
        u_long  rmx_hopcount;   /* max hops expected */
        u_long  rmx_expire;     /* lifetime for route, e.g. redirect */
        u_long  rmx_recvpipe;   /* inbound delay-bandwidth product */
        u_long  rmx_sendpipe;   /* outbound delay-bandwidth product */
        u_long  rmx_ssthresh;   /* outbound gateway buffer limit */
        u_long  rmx_rtt;        /* estimated round trip time */
        u_long  rmx_rttvar;     /* estimated rtt variance */
        u_long  rmx_pksent;     /* packets sent using this route */
        u_long  rmx_filler[4];  /* will be used for T/TCP later */
};

/*
 * Structures for routing messages.
 */
struct rt_msghdr {
        u_short rtm_msglen;     /* to skip over non-understood messages */
        u_char  rtm_version;    /* future binary compatibility */
        u_char  rtm_type;       /* message type */
        u_short rtm_index;      /* index for associated ifp */
        int     rtm_flags;      /* flags, incl. kern & message, e.g. DONE */
        int     rtm_addrs;      /* bitmask identifying sockaddrs in msg */
        pid_t   rtm_pid;        /* identify sender */
        int     rtm_seq;        /* for sender to identify action */
        int     rtm_errno;      /* why failed */
        int     rtm_use;        /* from rtentry */
        u_long  rtm_inits;      /* which metrics we are initializing */
        struct  rt_metrics rtm_rmx; /* metrics themselves */
};

struct {
  struct rt_msghdr m_rtm;
  char       m_space[512];
} m_rtmsg;

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

static bool
get_default_gateway (in_addr_t *ret)
{
  struct gc_arena gc = gc_new ();
  int s, seq, l, pid, rtm_addrs, i;
  struct sockaddr so_dst, so_mask;
  char *cp = m_rtmsg.m_space; 
  struct sockaddr *gate = NULL, *sa;
  struct  rt_msghdr *rtm_aux;

#define NEXTADDR(w, u) \
        if (rtm_addrs & (w)) {\
            l = ROUNDUP(u.sa_len); memmove(cp, &(u), l); cp += l;\
        }

#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

#define rtm m_rtmsg.m_rtm

  pid = getpid();
  seq = 0;
  rtm_addrs = RTA_DST | RTA_NETMASK;

  bzero(&so_dst, sizeof(so_dst));
  bzero(&so_mask, sizeof(so_mask));
  bzero(&rtm, sizeof(struct rt_msghdr));

  rtm.rtm_type = RTM_GET;
  rtm.rtm_flags = RTF_UP | RTF_GATEWAY;
  rtm.rtm_version = RTM_VERSION;
  rtm.rtm_seq = ++seq;
  rtm.rtm_addrs = rtm_addrs; 

  so_dst.sa_family = AF_INET;
  so_dst.sa_len = sizeof(struct sockaddr_in);
  so_mask.sa_family = AF_INET;
  so_mask.sa_len = sizeof(struct sockaddr_in);

  NEXTADDR(RTA_DST, so_dst);
  NEXTADDR(RTA_NETMASK, so_mask);

  rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;

  s = socket(PF_ROUTE, SOCK_RAW, 0);

  if (write(s, (char *)&m_rtmsg, l) < 0)
    {
      msg (M_WARN, "ROUTE: problem writing to routing socket");
      gc_free (&gc);
      close(s);
      return false;
    }

  do {
    l = read(s, (char *)&m_rtmsg, sizeof(m_rtmsg));
  } while (l > 0 && (rtm.rtm_seq != seq || rtm.rtm_pid != pid));
                        
  close(s);

  rtm_aux = &rtm;

  cp = ((char *)(rtm_aux + 1));
  if (rtm_aux->rtm_addrs) {
    for (i = 1; i; i <<= 1)
      if (i & rtm_aux->rtm_addrs) {
	sa = (struct sockaddr *)cp;
	if (i == RTA_GATEWAY )
	  gate = sa;
	ADVANCE(cp, sa);
      }
  }
  else
    {
      gc_free (&gc);
      return false;
    }


  if (gate != NULL )
    {
      *ret = ntohl(((struct sockaddr_in *)gate)->sin_addr.s_addr);
#if 1
      msg (M_INFO, "gw %s",
	   print_in_addr_t ((in_addr_t) *ret, 0, &gc));
#endif

      gc_free (&gc);
      return true;
    }
  else
    {
      gc_free (&gc);
      return false;
    }
}

#elif defined(TARGET_OPENBSD) || defined(TARGET_NETBSD)

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* all of this is taken from <net/route.h> in OpenBSD 3.6 */
#define RTA_DST		0x1	/* destination sockaddr present */
#define RTA_GATEWAY	0x2	/* gateway sockaddr present */
#define RTA_NETMASK	0x4	/* netmask sockaddr present */

#define RTM_GET		0x4	/* Report Metrics */

#define RTM_VERSION	3	/* Up the ante and ignore older versions */

#define	RTF_UP		0x1		/* route usable */
#define	RTF_GATEWAY	0x2		/* destination is a gateway */

/*
 * Huge version for userland compatibility.
 */
struct rt_metrics {
	u_long	rmx_locks;	/* Kernel must leave these values alone */
	u_long	rmx_mtu;	/* MTU for this path */
	u_long	rmx_hopcount;	/* max hops expected */
	u_long	rmx_expire;	/* lifetime for route, e.g. redirect */
	u_long	rmx_recvpipe;	/* inbound delay-bandwidth product */
	u_long	rmx_sendpipe;	/* outbound delay-bandwidth product */
	u_long	rmx_ssthresh;	/* outbound gateway buffer limit */
	u_long	rmx_rtt;	/* estimated round trip time */
	u_long	rmx_rttvar;	/* estimated rtt variance */
	u_long	rmx_pksent;	/* packets sent using this route */
};

/*
 * Structures for routing messages.
 */
struct rt_msghdr {
	u_short	rtm_msglen;	/* to skip over non-understood messages */
	u_char	rtm_version;	/* future binary compatibility */
	u_char	rtm_type;	/* message type */
	u_short	rtm_index;	/* index for associated ifp */
	int	rtm_flags;	/* flags, incl. kern & message, e.g. DONE */
	int	rtm_addrs;	/* bitmask identifying sockaddrs in msg */
	pid_t	rtm_pid;	/* identify sender */
	int	rtm_seq;	/* for sender to identify action */
	int	rtm_errno;	/* why failed */
	int	rtm_use;	/* from rtentry */
	u_long	rtm_inits;	/* which metrics we are initializing */
	struct	rt_metrics rtm_rmx; /* metrics themselves */
};

struct {
  struct rt_msghdr m_rtm;
  char       m_space[512];
} m_rtmsg;

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

static bool
get_default_gateway (in_addr_t *ret)
{
  struct gc_arena gc = gc_new ();
  int s, seq, l, rtm_addrs, i;
  pid_t pid;
  struct sockaddr so_dst, so_mask;
  char *cp = m_rtmsg.m_space; 
  struct sockaddr *gate = NULL, *sa;
  struct  rt_msghdr *rtm_aux;

#define NEXTADDR(w, u) \
        if (rtm_addrs & (w)) {\
            l = ROUNDUP(u.sa_len); memmove(cp, &(u), l); cp += l;\
        }

#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

#define rtm m_rtmsg.m_rtm

  pid = getpid();
  seq = 0;
  rtm_addrs = RTA_DST | RTA_NETMASK;

  bzero(&so_dst, sizeof(so_dst));
  bzero(&so_mask, sizeof(so_mask));
  bzero(&rtm, sizeof(struct rt_msghdr));

  rtm.rtm_type = RTM_GET;
  rtm.rtm_flags = RTF_UP | RTF_GATEWAY;
  rtm.rtm_version = RTM_VERSION;
  rtm.rtm_seq = ++seq;
  rtm.rtm_addrs = rtm_addrs; 

  so_dst.sa_family = AF_INET;
  so_dst.sa_len = sizeof(struct sockaddr_in);
  so_mask.sa_family = AF_INET;
  so_mask.sa_len = sizeof(struct sockaddr_in);

  NEXTADDR(RTA_DST, so_dst);
  NEXTADDR(RTA_NETMASK, so_mask);

  rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;

  s = socket(PF_ROUTE, SOCK_RAW, 0);

  if (write(s, (char *)&m_rtmsg, l) < 0)
    {
      warn("writing to routing socket");
      gc_free (&gc);
      close(s);
      return false;
    }

  do {
    l = read(s, (char *)&m_rtmsg, sizeof(m_rtmsg));
  } while (l > 0 && (rtm.rtm_seq != seq || rtm.rtm_pid != pid));
                        
  close(s);

  rtm_aux = &rtm;

  cp = ((char *)(rtm_aux + 1));
  if (rtm_aux->rtm_addrs) {
    for (i = 1; i; i <<= 1)
      if (i & rtm_aux->rtm_addrs) {
	sa = (struct sockaddr *)cp;
	if (i == RTA_GATEWAY )
	  gate = sa;
	ADVANCE(cp, sa);
      }
  }
  else
    {
      gc_free (&gc);
      return false;
    }


  if (gate != NULL )
    {
      *ret = ntohl(((struct sockaddr_in *)gate)->sin_addr.s_addr);
#if 1
      msg (M_INFO, "gw %s",
	   print_in_addr_t ((in_addr_t) *ret, 0, &gc));
#endif

      gc_free (&gc);
      return true;
    }
  else
    {
      gc_free (&gc);
      return false;
    }
}

#else

static bool
get_default_gateway (in_addr_t *ret)
{
  return false;
}

#endif

bool
netmask_to_netbits (const in_addr_t network, const in_addr_t netmask, int *netbits)
{
  int i;
  const int addrlen = sizeof (in_addr_t) * 8;

  if ((network & netmask) == network)
    {
      for (i = 0; i <= addrlen; ++i)
	{
	  in_addr_t mask = netbits_to_netmask (i);
	  if (mask == netmask)
	    {
	      if (i == addrlen)
		*netbits = -1;
	      else
		*netbits = i;
	      return true;
	    }
	}
    }
  return false;
}
