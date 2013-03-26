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
 * Support routines for adding/deleting network routes.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "common.h"
#include "error.h"
#include "route.h"
#include "misc.h"
#include "socket.h"
#include "manage.h"
#include "win32.h"
#include "options.h"

#include "memdbg.h"

#ifdef WIN32
#define METRIC_NOT_USED ((DWORD)-1)
#endif

static void delete_route (struct route *r, const struct tuntap *tt, unsigned int flags, const struct route_gateway_info *rgi, const struct env_set *es);

static void get_bypass_addresses (struct route_bypass *rb, const unsigned int flags);

#ifdef ENABLE_DEBUG

static void
print_bypass_addresses (const struct route_bypass *rb)
{
  struct gc_arena gc = gc_new ();
  int i;
  for (i = 0; i < rb->n_bypass; ++i)
    {
      msg (D_ROUTE, "ROUTE: bypass_host_route[%d]=%s",
	   i,
	   print_in_addr_t (rb->bypass[i], 0, &gc));
    }
  gc_free (&gc);
}

#endif

static bool
add_bypass_address (struct route_bypass *rb, const in_addr_t a)
{
  int i;
  for (i = 0; i < rb->n_bypass; ++i)
    {
      if (a == rb->bypass[i]) /* avoid duplicates */
	return true;
    }
  if (rb->n_bypass < N_ROUTE_BYPASS)
    {
      rb->bypass[rb->n_bypass++] = a;
      return true;
    }
  else
    {
      return false;
    }
}

struct route_option_list *
new_route_option_list (const int max_routes, struct gc_arena *a)
{
  struct route_option_list *ret;
  ALLOC_VAR_ARRAY_CLEAR_GC (ret, struct route_option_list, struct route_option, max_routes, a);
  ret->capacity = max_routes;
  return ret;
}

struct route_ipv6_option_list *
new_route_ipv6_option_list (const int max_routes, struct gc_arena *a)
{
  struct route_ipv6_option_list *ret;
  ALLOC_VAR_ARRAY_CLEAR_GC (ret, struct route_ipv6_option_list, struct route_ipv6_option, max_routes, a);
  ret->capacity = max_routes;
  return ret;
}

struct route_option_list *
clone_route_option_list (const struct route_option_list *src, struct gc_arena *a)
{
  const size_t rl_size = array_mult_safe (sizeof(struct route_option), src->capacity, sizeof(struct route_option_list));
  struct route_option_list *ret = gc_malloc (rl_size, false, a);
  memcpy (ret, src, rl_size);
  return ret;
}

struct route_ipv6_option_list *
clone_route_ipv6_option_list (const struct route_ipv6_option_list *src, struct gc_arena *a)
{
  const size_t rl_size = array_mult_safe (sizeof(struct route_ipv6_option), src->capacity, sizeof(struct route_ipv6_option_list));
  struct route_ipv6_option_list *ret = gc_malloc (rl_size, false, a);
  memcpy (ret, src, rl_size);
  return ret;
}

void
copy_route_option_list (struct route_option_list *dest, const struct route_option_list *src)
{
  const size_t src_size = array_mult_safe (sizeof(struct route_option), src->capacity, sizeof(struct route_option_list));
  if (src->capacity > dest->capacity)
    msg (M_FATAL, PACKAGE_NAME " ROUTE: (copy) number of route options in src (%d) is greater than route list capacity in dest (%d)", src->capacity, dest->capacity);
  memcpy (dest, src, src_size);
}

void
copy_route_ipv6_option_list (struct route_ipv6_option_list *dest,
			     const struct route_ipv6_option_list *src)
{
  const size_t src_size = array_mult_safe (sizeof(struct route_ipv6_option), src->capacity, sizeof(struct route_ipv6_option_list));
  if (src->capacity > dest->capacity)
    msg (M_FATAL, PACKAGE_NAME " ROUTE: (copy) number of route options in src (%d) is greater than route list capacity in dest (%d)", src->capacity, dest->capacity);
  memcpy (dest, src, src_size);
}

struct route_list *
new_route_list (const int max_routes, struct gc_arena *a)
{
  struct route_list *ret;
  ALLOC_VAR_ARRAY_CLEAR_GC (ret, struct route_list, struct route, max_routes, a);
  ret->capacity = max_routes;
  return ret;
}

struct route_ipv6_list *
new_route_ipv6_list (const int max_routes, struct gc_arena *a)
{
  struct route_ipv6_list *ret;
  ALLOC_VAR_ARRAY_CLEAR_GC (ret, struct route_ipv6_list, struct route_ipv6, max_routes, a);
  ret->capacity = max_routes;
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
  if (r->flags & RT_METRIC_DEFINED)
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
get_special_addr (const struct route_list *rl,
		  const char *string,
		  in_addr_t *out,
		  bool *status)
{
  if (status)
    *status = true;
  if (!strcmp (string, "vpn_gateway"))
    {
      if (rl)
	{
	  if (rl->spec.flags & RTSA_REMOTE_ENDPOINT)
	    *out = rl->spec.remote_endpoint;
	  else
	    {
	      msg (M_INFO, PACKAGE_NAME " ROUTE: vpn_gateway undefined");
	      if (status)
		*status = false;
	    }
	}
      return true;
    }
  else if (!strcmp (string, "net_gateway"))
    {
      if (rl)
	{
	  if (rl->rgi.flags & RGI_ADDR_DEFINED)
	    *out = rl->rgi.gateway.addr;
	  else
	    {
	      msg (M_INFO, PACKAGE_NAME " ROUTE: net_gateway undefined -- unable to get default gateway from system");
	      if (status)
		*status = false;
	    }
	}
      return true;
    }
  else if (!strcmp (string, "remote_host"))
    {
      if (rl)
	{
	  if (rl->spec.flags & RTSA_REMOTE_HOST)
	    *out = rl->spec.remote_host;
	  else
	    {
	      msg (M_INFO, PACKAGE_NAME " ROUTE: remote_host undefined");
	      if (status)
		*status = false;
	    }
	}
      return true;
    }
  return false;
}

bool
is_special_addr (const char *addr_str)
{
  if (addr_str)
    return get_special_addr (NULL, addr_str, NULL, NULL);
  else
    return false;
}

static bool
init_route (struct route *r,
	    struct addrinfo **network_list,
	    const struct route_option *ro,
	    const struct route_list *rl)
{
  const in_addr_t default_netmask = IPV4_NETMASK_HOST;
  bool status;
  int ret;
  struct in_addr special;

  CLEAR (*r);
  r->option = ro;

  /* network */

  if (!is_route_parm_defined (ro->network))
    {
      goto fail;
    }


  /* get_special_addr replaces specialaddr with a special ip addr
     like gw. getaddrinfo is called to convert a a addrinfo struct */

  if(get_special_addr (rl, ro->network, &special.s_addr, &status))
    {
      special.s_addr = htonl(special.s_addr);
      ret = openvpn_getaddrinfo(0, inet_ntoa(special), 0, NULL,
                                AF_INET, network_list);
    }
  else
    ret = openvpn_getaddrinfo(GETADDR_RESOLVE | GETADDR_WARN_ON_SIGNAL,
                              ro->network, 0, NULL, AF_INET, network_list);

  status = (ret == 0);

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
      if (!get_special_addr (rl, ro->gateway, &r->gateway, &status))
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
      if (rl->spec.flags & RTSA_REMOTE_ENDPOINT)
	r->gateway = rl->spec.remote_endpoint;
      else
	{
	  msg (M_WARN, PACKAGE_NAME " ROUTE: " PACKAGE_NAME " needs a gateway parameter for a --route option and no default was specified by either --route-gateway or --ifconfig options");
	  goto fail;
	}
    }

  /* metric */

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
      r->flags |= RT_METRIC_DEFINED;
    }
  else if (rl->spec.flags & RTSA_DEFAULT_METRIC)
    {
      r->metric = rl->spec.default_metric;
      r->flags |= RT_METRIC_DEFINED;
    }

  r->flags |= RT_DEFINED;

  return true;

 fail:
  msg (M_WARN, PACKAGE_NAME " ROUTE: failed to parse/resolve route for host/network: %s",
       ro->network);
  return false;
}

static bool
init_route_ipv6 (struct route_ipv6 *r6,
	         const struct route_ipv6_option *r6o,
	         const struct route_ipv6_list *rl6 )
{
  r6->defined = false;

  if ( !get_ipv6_addr( r6o->prefix, &r6->network, &r6->netbits, NULL, M_WARN ))
    goto fail;

  /* gateway */
  if (is_route_parm_defined (r6o->gateway))
    {
      if ( inet_pton( AF_INET6, r6o->gateway, &r6->gateway ) != 1 )
        {
	  msg( M_WARN, PACKAGE_NAME "ROUTE6: cannot parse gateway spec '%s'", r6o->gateway );
        }
    }
  else if (rl6->remote_endpoint_defined)
    {
      r6->gateway = rl6->remote_endpoint_ipv6;
    }
  else
    {
      msg (M_WARN, PACKAGE_NAME " ROUTE6: " PACKAGE_NAME " needs a gateway parameter for a --route-ipv6 option and no default was specified by either --route-ipv6-gateway or --ifconfig-ipv6 options");
      goto fail;
    }

  /* metric */

  r6->metric_defined = false;
  r6->metric = -1;
  if (is_route_parm_defined (r6o->metric))
    {
      r6->metric = atoi (r6o->metric);
      if (r6->metric < 0)
	{
	  msg (M_WARN, PACKAGE_NAME " ROUTE: route metric for network %s (%s) must be >= 0",
	       r6o->prefix,
	       r6o->metric);
	  goto fail;
	}
      r6->metric_defined = true;
    }
  else if (rl6->default_metric_defined)
    {
      r6->metric = rl6->default_metric;
      r6->metric_defined = true;
    }

  r6->defined = true;

  return true;

 fail:
  msg (M_WARN, PACKAGE_NAME " ROUTE: failed to parse/resolve route for host/network: %s",
       r6o->prefix);
  r6->defined = false;
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
  if (l->n >= l->capacity)
    msg (M_FATAL, PACKAGE_NAME " ROUTE: cannot add more than %d routes -- please increase the max-routes option in the client configuration file",
	 l->capacity);
  ro = &l->routes[l->n];
  ro->network = network;
  ro->netmask = netmask;
  ro->gateway = gateway;
  ro->metric = metric;
  ++l->n;
}

void
add_route_ipv6_to_option_list (struct route_ipv6_option_list *l,
			  const char *prefix,
			  const char *gateway,
			  const char *metric)
{
  struct route_ipv6_option *ro;
  if (l->n >= l->capacity)
    msg (M_FATAL, PACKAGE_NAME " ROUTE: cannot add more than %d IPv6 routes -- please increase the max-routes option in the client configuration file",
	 l->capacity);
  ro = &l->routes_ipv6[l->n];
  ro->prefix = prefix;
  ro->gateway = gateway;
  ro->metric = metric;
  ++l->n;
}

void
clear_route_list (struct route_list *rl)
{
  const int capacity = rl->capacity;
  const size_t rl_size = array_mult_safe (sizeof(struct route), capacity, sizeof(struct route_list));
  memset(rl, 0, rl_size);
  rl->capacity = capacity;
}

void
clear_route_ipv6_list (struct route_ipv6_list *rl6)
{
  const int capacity = rl6->capacity;
  const size_t rl6_size = array_mult_safe (sizeof(struct route_ipv6), capacity, sizeof(struct route_ipv6_list));
  memset(rl6, 0, rl6_size);
  rl6->capacity = capacity;
}

void
route_list_add_vpn_gateway (struct route_list *rl,
			    struct env_set *es,
			    const in_addr_t addr)
{
  rl->spec.remote_endpoint = addr;
  rl->spec.flags |= RTSA_REMOTE_ENDPOINT;
  setenv_route_addr (es, "vpn_gateway", rl->spec.remote_endpoint, -1);
}

static void
add_block_local_item (struct route_list *rl,
		      const struct route_gateway_address *gateway,
		      in_addr_t target)
{
  const int rgi_needed = (RGI_ADDR_DEFINED|RGI_NETMASK_DEFINED);
  if ((rl->rgi.flags & rgi_needed) == rgi_needed
      && rl->rgi.gateway.netmask < 0xFFFFFFFF
      && (rl->n)+2 <= rl->capacity)
    {
      struct route r;
      unsigned int l2;

      /* split a route into two smaller blocking routes, and direct them to target */
      CLEAR(r);
      r.flags = RT_DEFINED;
      r.gateway = target;
      r.network = gateway->addr & gateway->netmask;
      l2 = ((~gateway->netmask)+1)>>1;
      r.netmask = ~(l2-1);
      rl->routes[rl->n++] = r;
      r.network += l2;
      rl->routes[rl->n++] = r;
    }
}

static void
add_block_local (struct route_list *rl)
{
  const int rgi_needed = (RGI_ADDR_DEFINED|RGI_NETMASK_DEFINED);
  if ((rl->flags & RG_BLOCK_LOCAL)
      && (rl->rgi.flags & rgi_needed) == rgi_needed
      && (rl->spec.flags & RTSA_REMOTE_ENDPOINT)
      && rl->spec.remote_host_local != TLA_LOCAL)
    {
      size_t i;

      /* add bypass for gateway addr */
      add_bypass_address (&rl->spec.bypass, rl->rgi.gateway.addr);

      /* block access to local subnet */
      add_block_local_item (rl, &rl->rgi.gateway, rl->spec.remote_endpoint);

      /* process additional subnets on gateway interface */
      for (i = 0; i < rl->rgi.n_addrs; ++i)
	{
	  const struct route_gateway_address *gwa = &rl->rgi.addrs[i];
	  /* omit the add/subnet in &rl->rgi which we processed above */
	  if (!((rl->rgi.gateway.addr & rl->rgi.gateway.netmask) == (gwa->addr & gwa->netmask)
		&& rl->rgi.gateway.netmask == gwa->netmask))
	    add_block_local_item (rl, gwa, rl->spec.remote_endpoint);
	}
    }
}

bool
init_route_list (struct route_list *rl,
		 const struct route_option_list *opt,
		 const char *remote_endpoint,
		 int default_metric,
		 in_addr_t remote_host,
		 struct env_set *es)
{
  struct gc_arena gc = gc_new ();
  bool ret = true;

  clear_route_list (rl);

  rl->flags = opt->flags;

  if (remote_host)
    {
      rl->spec.remote_host = remote_host;
      rl->spec.flags |= RTSA_REMOTE_HOST;
    }

  if (default_metric)
    {
      rl->spec.default_metric = default_metric;
      rl->spec.flags |= RTSA_DEFAULT_METRIC;
    }

  get_default_gateway (&rl->rgi);
  if (rl->rgi.flags & RGI_ADDR_DEFINED)
    {
      setenv_route_addr (es, "net_gateway", rl->rgi.gateway.addr, -1);
#ifdef ENABLE_DEBUG
      print_default_gateway (D_ROUTE, &rl->rgi);
#endif
    }
  else
    {
      dmsg (D_ROUTE, "ROUTE: default_gateway=UNDEF");
    }

  if (rl->spec.flags & RTSA_REMOTE_HOST)
    rl->spec.remote_host_local = test_local_addr (remote_host, &rl->rgi);

  if (is_route_parm_defined (remote_endpoint))
    {
      bool defined = false;
      rl->spec.remote_endpoint = getaddr (
				     GETADDR_RESOLVE
				     | GETADDR_HOST_ORDER
				     | GETADDR_WARN_ON_SIGNAL,
				     remote_endpoint,
				     0,
				     &defined,
				     NULL);

      if (defined)
	{
	  setenv_route_addr (es, "vpn_gateway", rl->spec.remote_endpoint, -1);
	  rl->spec.flags |= RTSA_REMOTE_ENDPOINT;
	}
      else
	{
	  msg (M_WARN, PACKAGE_NAME " ROUTE: failed to parse/resolve default gateway: %s",
	       remote_endpoint);
	  ret = false;
	}
    }

  if (rl->flags & RG_ENABLE)
    {
      add_block_local (rl);
      get_bypass_addresses (&rl->spec.bypass, rl->flags);
#ifdef ENABLE_DEBUG
      print_bypass_addresses (&rl->spec.bypass);
#endif
    }

  /* parse the routes from opt to rl */
  {
    int i = 0;
    int j = rl->n;
    bool warned = false;
    for (i = 0; i < opt->n; ++i)
      {
        struct addrinfo* netlist;
	struct route r;

	if (!init_route (&r,
			 &netlist,
			 &opt->routes[i],
			 rl))
	  ret = false;
	else
	  {
            struct addrinfo* curele;
            for (curele	= netlist; curele; curele = curele->ai_next)
	      {
		if (j < rl->capacity)
		  {
                    r.network = ntohl(((struct sockaddr_in*)(curele)->ai_addr)->sin_addr.s_addr);
		    rl->routes[j++] = r;
		  }
		else
		  {
		    if (!warned)
		      {
			msg (M_WARN, PACKAGE_NAME " ROUTE: routes dropped because number of expanded routes is greater than route list capacity (%d)", rl->capacity);
			warned = true;
		      }
		  }
	      }
            freeaddrinfo(netlist);
	  }
      }
    rl->n = j;
  }

  gc_free (&gc);
  return ret;
}

bool
init_route_ipv6_list (struct route_ipv6_list *rl6,
		 const struct route_ipv6_option_list *opt6,
		 const char *remote_endpoint,
		 int default_metric,
		 struct env_set *es)
{
  struct gc_arena gc = gc_new ();
  bool ret = true;

  clear_route_ipv6_list (rl6);

  rl6->flags = opt6->flags;

  if (default_metric >= 0 )
    {
      rl6->default_metric = default_metric;
      rl6->default_metric_defined = true;
    }

  /* "default_gateway" is stuff for "redirect-gateway", which we don't
   * do for IPv6 yet -> TODO
   */
    {
      dmsg (D_ROUTE, "ROUTE6: default_gateway=UNDEF");
    }

  if ( is_route_parm_defined( remote_endpoint ))
    {
      if ( inet_pton( AF_INET6, remote_endpoint, 
			&rl6->remote_endpoint_ipv6) == 1 )
        {
	  rl6->remote_endpoint_defined = true;
        }
      else
	{
	  msg (M_WARN, PACKAGE_NAME " ROUTE: failed to parse/resolve default gateway: %s", remote_endpoint);
          ret = false;
	}
    }
  else
    rl6->remote_endpoint_defined = false;


  if (!(opt6->n >= 0 && opt6->n <= rl6->capacity))
    msg (M_FATAL, PACKAGE_NAME " ROUTE6: (init) number of route options (%d) is greater than route list capacity (%d)", opt6->n, rl6->capacity);

  /* parse the routes from opt to rl6 */
  {
    int i, j = 0;
    for (i = 0; i < opt6->n; ++i)
      {
	if (!init_route_ipv6 (&rl6->routes_ipv6[j],
			      &opt6->routes_ipv6[i],
			      rl6 ))
	  ret = false;
	else
	  ++j;
      }
    rl6->n = j;
  }

  gc_free (&gc);
  return ret;
}

static void
add_route3 (in_addr_t network,
	    in_addr_t netmask,
	    in_addr_t gateway,
	    const struct tuntap *tt,
	    unsigned int flags,
	    const struct route_gateway_info *rgi,
	    const struct env_set *es)
{
  struct route r;
  CLEAR (r);
  r.flags = RT_DEFINED;
  r.network = network;
  r.netmask = netmask;
  r.gateway = gateway;
  add_route (&r, tt, flags, rgi, es);
}

static void
del_route3 (in_addr_t network,
	    in_addr_t netmask,
	    in_addr_t gateway,
	    const struct tuntap *tt,
	    unsigned int flags,
	    const struct route_gateway_info *rgi,
	    const struct env_set *es)
{
  struct route r;
  CLEAR (r);
  r.flags = RT_DEFINED|RT_ADDED;
  r.network = network;
  r.netmask = netmask;
  r.gateway = gateway;
  delete_route (&r, tt, flags, rgi, es);
}

static void
add_bypass_routes (struct route_bypass *rb,
		   in_addr_t gateway,
		   const struct tuntap *tt,
		   unsigned int flags,
		   const struct route_gateway_info *rgi,
		   const struct env_set *es)
{
  int i;
  for (i = 0; i < rb->n_bypass; ++i)
    {
      if (rb->bypass[i])
	add_route3 (rb->bypass[i],
		    IPV4_NETMASK_HOST,
		    gateway,
		    tt,
		    flags | ROUTE_REF_GW,
		    rgi,
		    es);
    }
}

static void
del_bypass_routes (struct route_bypass *rb,
		   in_addr_t gateway,
		   const struct tuntap *tt,
		   unsigned int flags,
		   const struct route_gateway_info *rgi,
		   const struct env_set *es)
{
  int i;
  for (i = 0; i < rb->n_bypass; ++i)
    {
      if (rb->bypass[i])
	del_route3 (rb->bypass[i],
		    IPV4_NETMASK_HOST,
		    gateway,
		    tt,
		    flags | ROUTE_REF_GW,
		    rgi,
		    es);
    }
}

static void
redirect_default_route_to_vpn (struct route_list *rl, const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
  const char err[] = "NOTE: unable to redirect default gateway --";

  if ( rl && rl->flags & RG_ENABLE )
    {
      if (!(rl->spec.flags & RTSA_REMOTE_ENDPOINT))
	{
	  msg (M_WARN, "%s VPN gateway parameter (--route-gateway or --ifconfig) is missing", err);
	}
      else if (!(rl->rgi.flags & RGI_ADDR_DEFINED))
	{
	  msg (M_WARN, "%s Cannot read current default gateway from system", err);
	}
      else if (!(rl->spec.flags & RTSA_REMOTE_HOST))
	{
	  msg (M_WARN, "%s Cannot obtain current remote host address", err);
	}
      else
	{
	  bool local = BOOL_CAST(rl->flags & RG_LOCAL);
	  if (rl->flags & RG_AUTO_LOCAL) {
	    const int tla = rl->spec.remote_host_local;
	    if (tla == TLA_NONLOCAL)
	      {
		dmsg (D_ROUTE, "ROUTE remote_host is NOT LOCAL");
		local = false;
	      }
	    else if (tla == TLA_LOCAL)
	      {
		dmsg (D_ROUTE, "ROUTE remote_host is LOCAL");
		local = true;
	      }
	  }
	  if (!local)
	    {
	      /* route remote host to original default gateway */
	      /* if remote_host is not ipv4 (ie: ipv6), just skip
	       * adding this special /32 route */
	      if (rl->spec.remote_host != IPV4_INVALID_ADDR) {
		add_route3 (rl->spec.remote_host,
			    IPV4_NETMASK_HOST,
			    rl->rgi.gateway.addr,
			    tt,
			    flags | ROUTE_REF_GW,
			    &rl->rgi,
			    es);
		rl->iflags |= RL_DID_LOCAL;
	      } else {
		dmsg (D_ROUTE, "ROUTE remote_host protocol differs from tunneled");
	      }
	    }

	  /* route DHCP/DNS server traffic through original default gateway */
	  add_bypass_routes (&rl->spec.bypass, rl->rgi.gateway.addr, tt, flags, &rl->rgi, es);

	  if (rl->flags & RG_REROUTE_GW)
	    {
	      if (rl->flags & RG_DEF1)
		{
		  /* add new default route (1st component) */
		  add_route3 (0x00000000,
			      0x80000000,
			      rl->spec.remote_endpoint,
			      tt,
			      flags,
			      &rl->rgi,
			      es);

		  /* add new default route (2nd component) */
		  add_route3 (0x80000000,
			      0x80000000,
			      rl->spec.remote_endpoint,
			      tt,
			      flags,
			      &rl->rgi,
			      es);
		}
	      else
		{
		  /* delete default route */
		  del_route3 (0,
			      0,
			      rl->rgi.gateway.addr,
			      tt,
			      flags | ROUTE_REF_GW,
			      &rl->rgi,
			      es);

		  /* add new default route */
		  add_route3 (0,
			      0,
			      rl->spec.remote_endpoint,
			      tt,
			      flags,
			      &rl->rgi,
			      es);
		}
	    }

	  /* set a flag so we can undo later */
	  rl->iflags |= RL_DID_REDIRECT_DEFAULT_GATEWAY;
	}
    }
}

static void
undo_redirect_default_route_to_vpn (struct route_list *rl, const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
  if ( rl && rl->iflags & RL_DID_REDIRECT_DEFAULT_GATEWAY )
    {
      /* delete remote host route */
      if (rl->iflags & RL_DID_LOCAL)
	{
	  del_route3 (rl->spec.remote_host,
		      IPV4_NETMASK_HOST,
		      rl->rgi.gateway.addr,
		      tt,
		      flags | ROUTE_REF_GW,
		      &rl->rgi,
		      es);
	  rl->iflags &= ~RL_DID_LOCAL;
	}

      /* delete special DHCP/DNS bypass route */
      del_bypass_routes (&rl->spec.bypass, rl->rgi.gateway.addr, tt, flags, &rl->rgi, es);

      if (rl->flags & RG_REROUTE_GW)
	{
	  if (rl->flags & RG_DEF1)
	    {
	      /* delete default route (1st component) */
	      del_route3 (0x00000000,
			  0x80000000,
			  rl->spec.remote_endpoint,
			  tt,
			  flags,
			  &rl->rgi,
			  es);

	      /* delete default route (2nd component) */
	      del_route3 (0x80000000,
			  0x80000000,
			  rl->spec.remote_endpoint,
			  tt,
			  flags,
			  &rl->rgi,
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
			  &rl->rgi,
			  es);

	      /* restore original default route */
	      add_route3 (0,
			  0,
			  rl->rgi.gateway.addr,
			  tt,
			  flags | ROUTE_REF_GW,
			  &rl->rgi,
			  es);
	    }
	}

      rl->iflags &= ~RL_DID_REDIRECT_DEFAULT_GATEWAY;
    }
}

void
add_routes (struct route_list *rl, struct route_ipv6_list *rl6, const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
  redirect_default_route_to_vpn (rl, tt, flags, es);
  if ( rl && !(rl->iflags & RL_ROUTES_ADDED) )
    {
      int i;

#ifdef ENABLE_MANAGEMENT
      if (management && rl->n)
	{
	  management_set_state (management,
				OPENVPN_STATE_ADD_ROUTES,
				NULL,
				0,
				0);
	}
#endif
      
      for (i = 0; i < rl->n; ++i)
	{
	  struct route *r = &rl->routes[i];
	  check_subnet_conflict (r->network, r->netmask, "route");
	  if (flags & ROUTE_DELETE_FIRST)
	    delete_route (r, tt, flags, &rl->rgi, es);
	  add_route (r, tt, flags, &rl->rgi, es);
	}
      rl->iflags |= RL_ROUTES_ADDED;
    }
  if (rl6 && !rl6->routes_added)
    {
      int i;

      for (i = 0; i < rl6->n; ++i)
	{
	  struct route_ipv6 *r = &rl6->routes_ipv6[i];
	  if (flags & ROUTE_DELETE_FIRST)
	    delete_route_ipv6 (r, tt, flags, es);
	  add_route_ipv6 (r, tt, flags, es);
	}
      rl6->routes_added = true;
    }
}

void
delete_routes (struct route_list *rl, struct route_ipv6_list *rl6,
	       const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
  if ( rl && rl->iflags & RL_ROUTES_ADDED )
    {
      int i;
      for (i = rl->n - 1; i >= 0; --i)
	{
	  struct route * r = &rl->routes[i];
	  delete_route (r, tt, flags, &rl->rgi, es);
	}
      rl->iflags &= ~RL_ROUTES_ADDED;
    }

   undo_redirect_default_route_to_vpn (rl, tt, flags, es);

  if ( rl )
    {
      clear_route_list (rl);
    }

  if ( rl6 && rl6->routes_added )
    {
      int i;
      for (i = rl6->n - 1; i >= 0; --i)
	{
	  const struct route_ipv6 *r6 = &rl6->routes_ipv6[i];
	  delete_route_ipv6 (r6, tt, flags, es);
	}
      rl6->routes_added = false;
    }

  if ( rl6 )
    {
      clear_route_ipv6_list (rl6);
    }
}

#ifndef ENABLE_SMALL

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
  if (rol->flags & RG_ENABLE)
    msg (level, "  [redirect_default_gateway local=%d]",
	 (rol->flags & RG_LOCAL) != 0);
  for (i = 0; i < rol->n; ++i)
    print_route_option (&rol->routes[i], level);
}

void
print_default_gateway(const int msglevel, const struct route_gateway_info *rgi)
{
  struct gc_arena gc = gc_new ();
  if (rgi->flags & RGI_ADDR_DEFINED)
    {
      struct buffer out = alloc_buf_gc (256, &gc);
      buf_printf (&out, "ROUTE_GATEWAY");
      if (rgi->flags & RGI_ON_LINK)
	buf_printf (&out, " ON_LINK");
      else
	buf_printf (&out, " %s", print_in_addr_t (rgi->gateway.addr, 0, &gc));
      if (rgi->flags & RGI_NETMASK_DEFINED)
	buf_printf (&out, "/%s", print_in_addr_t (rgi->gateway.netmask, 0, &gc));
#ifdef WIN32
      if (rgi->flags & RGI_IFACE_DEFINED)
	buf_printf (&out, " I=%u", (unsigned int)rgi->adapter_index);
#else
      if (rgi->flags & RGI_IFACE_DEFINED)
	buf_printf (&out, " IFACE=%s", rgi->iface);
#endif
      if (rgi->flags & RGI_HWADDR_DEFINED)
	buf_printf (&out, " HWADDR=%s", format_hex_ex (rgi->hwaddr, 6, 0, 1, ":", &gc));
      msg (msglevel, "%s", BSTR (&out));
    }
  gc_free (&gc);
}

#endif

static void
print_route (const struct route *r, int level)
{
  struct gc_arena gc = gc_new ();
  if (r->flags & RT_DEFINED)
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
  if (r->flags & RT_DEFINED)
    {
      setenv_route_addr (es, "network", r->network, i);
      setenv_route_addr (es, "netmask", r->netmask, i);
      setenv_route_addr (es, "gateway", r->gateway, i);

      if (r->flags & RT_METRIC_DEFINED)
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
setenv_route_ipv6 (struct env_set *es, const struct route_ipv6 *r6, int i)
{
  struct gc_arena gc = gc_new ();
  if (r6->defined)
    {
      struct buffer name1 = alloc_buf_gc( 256, &gc );
      struct buffer val = alloc_buf_gc( 256, &gc );
      struct buffer name2 = alloc_buf_gc( 256, &gc );

      buf_printf( &name1, "route_ipv6_network_%d", i );
      buf_printf( &val, "%s/%d", print_in6_addr( r6->network, 0, &gc ),
				 r6->netbits );
      setenv_str( es, BSTR(&name1), BSTR(&val) );

      buf_printf( &name2, "route_ipv6_gateway_%d", i );
      setenv_str( es, BSTR(&name2), print_in6_addr( r6->gateway, 0, &gc ));
    }
  gc_free (&gc);
}
void
setenv_routes_ipv6 (struct env_set *es, const struct route_ipv6_list *rl6)
{
  int i;
  for (i = 0; i < rl6->n; ++i)
    setenv_route_ipv6 (es, &rl6->routes_ipv6[i], i + 1);
}

/*
 * local_route() determines whether the gateway of a provided host
 * route is on the same interface that owns the default gateway.
 * It uses the data structure
 * returned by get_default_gateway() (struct route_gateway_info)
 * to determine this.  If the route is local, LR_MATCH is returned.
 * When adding routes into the kernel, if LR_MATCH is defined for
 * a given route, the route should explicitly reference the default
 * gateway interface as the route destination.  For example, here
 * is an example on Linux that uses LR_MATCH:
 *
 *   route add -net 10.10.0.1 netmask 255.255.255.255 dev eth0
 *
 * This capability is needed by the "default-gateway block-local"
 * directive, to allow client access to the local subnet to be
 * blocked but still allow access to the local default gateway.
 */

/* local_route() return values */
#define LR_NOMATCH 0 /* route is not local */
#define LR_MATCH   1 /* route is local */
#define LR_ERROR   2 /* caller should abort adding route */

static int
local_route (in_addr_t network,
	     in_addr_t netmask,
	     in_addr_t gateway,
	     const struct route_gateway_info *rgi)
{
  /* set LR_MATCH on local host routes */
  const int rgi_needed = (RGI_ADDR_DEFINED|RGI_NETMASK_DEFINED|RGI_IFACE_DEFINED);
  if (rgi
      && (rgi->flags & rgi_needed) == rgi_needed
      && gateway == rgi->gateway.addr
      && netmask == 0xFFFFFFFF)
    {
      if (((network ^  rgi->gateway.addr) & rgi->gateway.netmask) == 0)
	return LR_MATCH;
      else
	{
	  /* examine additional subnets on gateway interface */
	  size_t i;
	  for (i = 0; i < rgi->n_addrs; ++i)
	    {
	      const struct route_gateway_address *gwa = &rgi->addrs[i];
	      if (((network ^ gwa->addr) & gwa->netmask) == 0)
		return LR_MATCH;
	    }
	}
    }
    return LR_NOMATCH;
}

/* Return true if the "on-link" form of the route should be used.  This is when the gateway for a
   a route is specified as an interface rather than an address. */
static inline bool
is_on_link (const int is_local_route, const unsigned int flags, const struct route_gateway_info *rgi)
{
  return rgi && (is_local_route == LR_MATCH || ((flags & ROUTE_REF_GW) && (rgi->flags & RGI_ON_LINK)));
}

void
add_route (struct route *r,
	   const struct tuntap *tt,
	   unsigned int flags,
	   const struct route_gateway_info *rgi, /* may be NULL */
	   const struct env_set *es)
{
  struct gc_arena gc;
  struct argv argv;
  const char *network;
  const char *netmask;
  const char *gateway;
  bool status = false;
  int is_local_route;

  if (!(r->flags & RT_DEFINED))
    return;

  gc_init (&gc);
  argv_init (&argv);

  network = print_in_addr_t (r->network, 0, &gc);
  netmask = print_in_addr_t (r->netmask, 0, &gc);
  gateway = print_in_addr_t (r->gateway, 0, &gc);

  is_local_route = local_route(r->network, r->netmask, r->gateway, rgi);
  if (is_local_route == LR_ERROR)
    goto done;

#if defined(TARGET_LINUX)
#ifdef ENABLE_IPROUTE
  /* FIXME -- add on-link support for ENABLE_IPROUTE */
  argv_printf (&argv, "%s route add %s/%d via %s",
  	      iproute_path,
	      network,
	      count_netmask_bits(netmask),
	      gateway);
  if (r->flags & RT_METRIC_DEFINED)
    argv_printf_cat (&argv, "metric %d", r->metric);

#else
  argv_printf (&argv, "%s add -net %s netmask %s",
	       ROUTE_PATH,
	       network,
	       netmask);
  if (r->flags & RT_METRIC_DEFINED)
    argv_printf_cat (&argv, "metric %d", r->metric);
  if (is_on_link (is_local_route, flags, rgi))
    argv_printf_cat (&argv, "dev %s", rgi->iface);
  else
    argv_printf_cat (&argv, "gw %s", gateway);

#endif  /*ENABLE_IPROUTE*/
  argv_msg (D_ROUTE, &argv);
  status = openvpn_execve_check (&argv, es, 0, "ERROR: Linux route add command failed");

#elif defined (WIN32)
  {
    DWORD ai = TUN_ADAPTER_INDEX_INVALID;
    argv_printf (&argv, "%s%sc ADD %s MASK %s %s",
		 get_win_sys_path(),
		 WIN_ROUTE_PATH_SUFFIX,
		 network,
		 netmask,
		 gateway);
    if (r->flags & RT_METRIC_DEFINED)
      argv_printf_cat (&argv, "METRIC %d", r->metric);
    if (is_on_link (is_local_route, flags, rgi))
      {
	ai = rgi->adapter_index;
	argv_printf_cat (&argv, "IF %u", (unsigned int)ai);
      }

    argv_msg (D_ROUTE, &argv);

    if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_IPAPI)
      {
	status = add_route_ipapi (r, tt, ai);
	msg (D_ROUTE, "Route addition via IPAPI %s", status ? "succeeded" : "failed");
      }
    else if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_EXE)
      {
	netcmd_semaphore_lock ();
	status = openvpn_execve_check (&argv, es, 0, "ERROR: Windows route add command failed");
	netcmd_semaphore_release ();
      }
    else if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_ADAPTIVE)
      {
	status = add_route_ipapi (r, tt, ai);
	msg (D_ROUTE, "Route addition via IPAPI %s [adaptive]", status ? "succeeded" : "failed");
	if (!status)
	  {
	    msg (D_ROUTE, "Route addition fallback to route.exe");
	    netcmd_semaphore_lock ();
	    status = openvpn_execve_check (&argv, es, 0, "ERROR: Windows route add command failed [adaptive]");
	    netcmd_semaphore_release ();
	  }
      }
    else
      {
	ASSERT (0);
      }
  }

#elif defined (TARGET_SOLARIS)

  /* example: route add 192.0.2.32 -netmask 255.255.255.224 somegateway */

  argv_printf (&argv, "%s add",
		ROUTE_PATH);

  argv_printf_cat (&argv, "%s -netmask %s %s",
	      network,
	      netmask,
	      gateway);

  /* Solaris can only distinguish between "metric 0" == "on-link on the
   * interface where the IP address given is configured" and "metric > 0"
   * == "use gateway specified" (no finer-grained route metrics available)
   *
   * More recent versions of Solaris can also do "-interface", but that
   * would break backwards compatibility with older versions for no gain.
   */
  if (r->flags & RT_METRIC_DEFINED )
    argv_printf_cat (&argv, "%d", r->metric);

  argv_msg (D_ROUTE, &argv);
  status = openvpn_execve_check (&argv, es, 0, "ERROR: Solaris route add command failed");

#elif defined(TARGET_FREEBSD)

  argv_printf (&argv, "%s add",
		ROUTE_PATH);

#if 0
  if (r->flags & RT_METRIC_DEFINED)
    argv_printf_cat (&argv, "-rtt %d", r->metric);
#endif

  argv_printf_cat (&argv, "-net %s %s %s",
	      network,
	      gateway,
	      netmask);

  /* FIXME -- add on-link support for FreeBSD */

  argv_msg (D_ROUTE, &argv);
  status = openvpn_execve_check (&argv, es, 0, "ERROR: FreeBSD route add command failed");

#elif defined(TARGET_DRAGONFLY)

  argv_printf (&argv, "%s add",
		ROUTE_PATH);

#if 0
  if (r->flags & RT_METRIC_DEFINED)
    argv_printf_cat (&argv, "-rtt %d", r->metric);
#endif

  argv_printf_cat (&argv, "-net %s %s %s",
	      network,
	      gateway,
	      netmask);

  /* FIXME -- add on-link support for Dragonfly */

  argv_msg (D_ROUTE, &argv);
  status = openvpn_execve_check (&argv, es, 0, "ERROR: DragonFly route add command failed");

#elif defined(TARGET_DARWIN)

  argv_printf (&argv, "%s add",
		ROUTE_PATH);

#if 0
  if (r->flags & RT_METRIC_DEFINED)
    argv_printf_cat (&argv, "-rtt %d", r->metric);
#endif

  if (is_on_link (is_local_route, flags, rgi))
    {
      /* Mac OS X route syntax for ON_LINK:
	 route add -cloning -net 10.10.0.1 -netmask 255.255.255.255 -interface en0 */
      argv_printf_cat (&argv, "-cloning -net %s -netmask %s -interface %s",
		       network,
		       netmask,
		       rgi->iface);
    }
  else
    {
      argv_printf_cat (&argv, "-net %s %s %s",
		       network,
		       gateway,
		       netmask);
    }

  argv_msg (D_ROUTE, &argv);
  status = openvpn_execve_check (&argv, es, 0, "ERROR: OS X route add command failed");

#elif defined(TARGET_OPENBSD) || defined(TARGET_NETBSD)

  argv_printf (&argv, "%s add",
		ROUTE_PATH);

#if 0
  if (r->flags & RT_METRIC_DEFINED)
    argv_printf_cat (&argv, "-rtt %d", r->metric);
#endif

  argv_printf_cat (&argv, "-net %s %s -netmask %s",
	      network,
	      gateway,
	      netmask);

  /* FIXME -- add on-link support for OpenBSD/NetBSD */

  argv_msg (D_ROUTE, &argv);
  status = openvpn_execve_check (&argv, es, 0, "ERROR: OpenBSD/NetBSD route add command failed");

#else
  msg (M_FATAL, "Sorry, but I don't know how to do 'route' commands on this operating system.  Try putting your routes in a --route-up script");
#endif

 done:
  if (status)
    r->flags |= RT_ADDED;
  else
    r->flags &= ~RT_ADDED;
  argv_reset (&argv);
  gc_free (&gc);
}


static const char * 
print_in6_addr_netbits_only( struct in6_addr network_copy, int netbits, 
                             struct gc_arena * gc)
{
  /* clear host bit parts of route 
   * (needed if routes are specified improperly, or if we need to 
   * explicitely setup/clear the "connected" network routes on some OSes)
   */
  int byte = 15;
  int bits_to_clear = 128 - netbits;

  while( byte >= 0 && bits_to_clear > 0 )
    {
      if ( bits_to_clear >= 8 )
	{ network_copy.s6_addr[byte--] = 0; bits_to_clear -= 8; }
      else
	{ network_copy.s6_addr[byte--] &= (0xff << bits_to_clear); bits_to_clear = 0; }
    }

  return print_in6_addr( network_copy, 0, gc);
}

void
add_route_ipv6 (struct route_ipv6 *r6, const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
  struct gc_arena gc;
  struct argv argv;

  const char *network;
  const char *gateway;
  bool status = false;
  const char *device = tt->actual_name;

  bool gateway_needed = false;

  if (!r6->defined)
    return;

  gc_init (&gc);
  argv_init (&argv);

  network = print_in6_addr_netbits_only( r6->network, r6->netbits, &gc);
  gateway = print_in6_addr( r6->gateway, 0, &gc);

  if ( !tt->ipv6 )
    {
      msg( M_INFO, "add_route_ipv6(): not adding %s/%d, no IPv6 on if %s",
		    network, r6->netbits, device );
      return;
    }

  msg( M_INFO, "add_route_ipv6(%s/%d -> %s metric %d) dev %s",
		network, r6->netbits, gateway, r6->metric, device );

  /*
   * Filter out routes which are essentially no-ops
   * (not currently done for IPv6)
   */

  /* On "tun" interface, we never set a gateway if the operating system
   * can do "route to interface" - it does not add value, as the target
   * dev already fully qualifies the route destination on point-to-point
   * interfaces.   OTOH, on "tap" interface, we must always set the
   * gateway unless the route is to be an on-link network
   */
  if ( tt->type == DEV_TYPE_TAP &&
                  !(r6->metric_defined && r6->metric == 0 ) )
    {
      gateway_needed = true;
    }

#if defined(TARGET_LINUX)
#ifdef ENABLE_IPROUTE
  argv_printf (&argv, "%s -6 route add %s/%d dev %s",
  	      iproute_path,
	      network,
	      r6->netbits,
	      device);
  if (gateway_needed)
    argv_printf_cat (&argv, "via %s", gateway);
  if (r6->metric_defined && r6->metric > 0 )
    argv_printf_cat (&argv, " metric %d", r6->metric);

#else
  argv_printf (&argv, "%s -A inet6 add %s/%d dev %s",
		ROUTE_PATH,
	      network,
	      r6->netbits,
	      device);
  if (gateway_needed)
    argv_printf_cat (&argv, "gw %s", gateway);
  if (r6->metric_defined && r6->metric > 0 )
    argv_printf_cat (&argv, " metric %d", r6->metric);
#endif  /*ENABLE_IPROUTE*/
  argv_msg (D_ROUTE, &argv);
  status = openvpn_execve_check (&argv, es, 0, "ERROR: Linux route -6/-A inet6 add command failed");

#elif defined (WIN32)

  /* netsh interface ipv6 add route 2001:db8::/32 MyTunDevice */
  argv_printf (&argv, "%s%sc interface ipv6 add route %s/%d %s",
	       get_win_sys_path(),
	       NETSH_PATH_SUFFIX,
	       network,
	       r6->netbits,
	       device);

  /* next-hop depends on TUN or TAP mode:
   * - in TAP mode, we use the "real" next-hop
   * - in TUN mode we use a special-case link-local address that the tapdrvr
   *   knows about and will answer ND (neighbor discovery) packets for
   */
  if ( tt->type == DEV_TYPE_TUN )
	argv_printf_cat( &argv, " %s", "fe80::8" );
  else
	argv_printf_cat( &argv, " %s", gateway );

#if 0
  if (r->metric_defined)
    argv_printf_cat (&argv, " METRIC %d", r->metric);
#endif

  /* in some versions of Windows, routes are persistent across reboots by
   * default, unless "store=active" is set (pointed out by Tony Lim, thanks)
   */
  argv_printf_cat( &argv, " store=active" );

  argv_msg (D_ROUTE, &argv);

  netcmd_semaphore_lock ();
  status = openvpn_execve_check (&argv, es, 0, "ERROR: Windows route add ipv6 command failed");
  netcmd_semaphore_release ();

#elif defined (TARGET_SOLARIS)

  /* example: route add -inet6 2001:db8::/32 somegateway 0 */

  /* for some weird reason, this does not work for me unless I set
   * "metric 0" - otherwise, the routes will be nicely installed, but
   * packets will just disappear somewhere.  So we use "0" now...
   */

  argv_printf (&argv, "%s add -inet6 %s/%d %s 0",
		ROUTE_PATH,
		network,
		r6->netbits,
		gateway );

  argv_msg (D_ROUTE, &argv);
  status = openvpn_execve_check (&argv, es, 0, "ERROR: Solaris route add -inet6 command failed");

#elif defined(TARGET_FREEBSD) || defined(TARGET_DRAGONFLY)

  argv_printf (&argv, "%s add -inet6 %s/%d",
		ROUTE_PATH,
	        network,
	        r6->netbits);

  if (gateway_needed)
    argv_printf_cat (&argv, "%s", gateway);
  else
    argv_printf_cat (&argv, "-iface %s", device);

  argv_msg (D_ROUTE, &argv);
  status = openvpn_execve_check (&argv, es, 0, "ERROR: *BSD route add -inet6 command failed");

#elif defined(TARGET_DARWIN) 

  argv_printf (&argv, "%s add -inet6 %s -prefixlen %d",
		ROUTE_PATH,
	        network, r6->netbits );

  if (gateway_needed)
    argv_printf_cat (&argv, "%s", gateway);
  else
    argv_printf_cat (&argv, "-iface %s", device);

  argv_msg (D_ROUTE, &argv);
  status = openvpn_execve_check (&argv, es, 0, "ERROR: MacOS X route add -inet6 command failed");

#elif defined(TARGET_OPENBSD)

  argv_printf (&argv, "%s add -inet6 %s -prefixlen %d %s",
		ROUTE_PATH,
	        network, r6->netbits, gateway );

  argv_msg (D_ROUTE, &argv);
  status = openvpn_execve_check (&argv, es, 0, "ERROR: OpenBSD route add -inet6 command failed");

#elif defined(TARGET_NETBSD)

  argv_printf (&argv, "%s add -inet6 %s/%d %s",
		ROUTE_PATH,
	        network, r6->netbits, gateway );

  argv_msg (D_ROUTE, &argv);
  status = openvpn_execve_check (&argv, es, 0, "ERROR: NetBSD route add -inet6 command failed");

#else
  msg (M_FATAL, "Sorry, but I don't know how to do 'route ipv6' commands on this operating system.  Try putting your routes in a --route-up script");
#endif

  r6->defined = status;
  argv_reset (&argv);
  gc_free (&gc);
}

static void
delete_route (struct route *r,
	      const struct tuntap *tt,
	      unsigned int flags,
	      const struct route_gateway_info *rgi,
	      const struct env_set *es)
{
  struct gc_arena gc;
  struct argv argv;
  const char *network;
  const char *netmask;
  const char *gateway;
  int is_local_route;

  if ((r->flags & (RT_DEFINED|RT_ADDED)) != (RT_DEFINED|RT_ADDED))
    return;

  gc_init (&gc);
  argv_init (&argv);

  network = print_in_addr_t (r->network, 0, &gc);
  netmask = print_in_addr_t (r->netmask, 0, &gc);
  gateway = print_in_addr_t (r->gateway, 0, &gc);

  is_local_route = local_route(r->network, r->netmask, r->gateway, rgi);
  if (is_local_route == LR_ERROR)
    goto done;

#if defined(TARGET_LINUX)
#ifdef ENABLE_IPROUTE
  argv_printf (&argv, "%s route del %s/%d",
  	      iproute_path,
	      network,
	      count_netmask_bits(netmask));
#else
  argv_printf (&argv, "%s del -net %s netmask %s",
	       ROUTE_PATH,
	       network,
	       netmask);
#endif /*ENABLE_IPROUTE*/
  if (r->flags & RT_METRIC_DEFINED)
    argv_printf_cat (&argv, "metric %d", r->metric);
  argv_msg (D_ROUTE, &argv);
  openvpn_execve_check (&argv, es, 0, "ERROR: Linux route delete command failed");

#elif defined (WIN32)
  
  argv_printf (&argv, "%s%sc DELETE %s MASK %s %s",
	       get_win_sys_path(),
	       WIN_ROUTE_PATH_SUFFIX,
	       network,
	       netmask,
	       gateway);

  argv_msg (D_ROUTE, &argv);

  if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_IPAPI)
    {
      const bool status = del_route_ipapi (r, tt);
      msg (D_ROUTE, "Route deletion via IPAPI %s", status ? "succeeded" : "failed");
    }
  else if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_EXE)
    {
      netcmd_semaphore_lock ();
      openvpn_execve_check (&argv, es, 0, "ERROR: Windows route delete command failed");
      netcmd_semaphore_release ();
    }
  else if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_ADAPTIVE)
    {
      const bool status = del_route_ipapi (r, tt);
      msg (D_ROUTE, "Route deletion via IPAPI %s [adaptive]", status ? "succeeded" : "failed");
      if (!status)
	{
	  msg (D_ROUTE, "Route deletion fallback to route.exe");
	  netcmd_semaphore_lock ();
	  openvpn_execve_check (&argv, es, 0, "ERROR: Windows route delete command failed [adaptive]");
	  netcmd_semaphore_release ();
	}
    }
  else
    {
      ASSERT (0);
    }

#elif defined (TARGET_SOLARIS)

  argv_printf (&argv, "%s delete %s -netmask %s %s",
		ROUTE_PATH,
	      network,
	      netmask,
	      gateway);

  argv_msg (D_ROUTE, &argv);
  openvpn_execve_check (&argv, es, 0, "ERROR: Solaris route delete command failed");

#elif defined(TARGET_FREEBSD)

  argv_printf (&argv, "%s delete -net %s %s %s",
		ROUTE_PATH,
	      network,
	      gateway,
	      netmask);

  argv_msg (D_ROUTE, &argv);
  openvpn_execve_check (&argv, es, 0, "ERROR: FreeBSD route delete command failed");

#elif defined(TARGET_DRAGONFLY)

  argv_printf (&argv, "%s delete -net %s %s %s",
		ROUTE_PATH,
	      network,
	      gateway,
	      netmask);

  argv_msg (D_ROUTE, &argv);
  openvpn_execve_check (&argv, es, 0, "ERROR: DragonFly route delete command failed");

#elif defined(TARGET_DARWIN)

  if (is_on_link (is_local_route, flags, rgi))
    {
      argv_printf (&argv, "%s delete -cloning -net %s -netmask %s -interface %s",
		   ROUTE_PATH,
		   network,
		   netmask,
		   rgi->iface);
    }
  else
    {
      argv_printf (&argv, "%s delete -net %s %s %s",
		   ROUTE_PATH,
		   network,
		   gateway,
		   netmask);
    }

  argv_msg (D_ROUTE, &argv);
  openvpn_execve_check (&argv, es, 0, "ERROR: OS X route delete command failed");

#elif defined(TARGET_OPENBSD) || defined(TARGET_NETBSD)

  argv_printf (&argv, "%s delete -net %s %s -netmask %s",
		ROUTE_PATH,
	      network,
	      gateway,
	      netmask);

  argv_msg (D_ROUTE, &argv);
  openvpn_execve_check (&argv, es, 0, "ERROR: OpenBSD/NetBSD route delete command failed");

#else
  msg (M_FATAL, "Sorry, but I don't know how to do 'route' commands on this operating system.  Try putting your routes in a --route-up script");
#endif

 done:
  r->flags &= ~RT_ADDED;
  argv_reset (&argv);
  gc_free (&gc);
}

void
delete_route_ipv6 (const struct route_ipv6 *r6, const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
  struct gc_arena gc;
  struct argv argv;
  const char *network;
  const char *gateway;
  const char *device = tt->actual_name;
  bool gateway_needed = false;

  if (!r6->defined)
    return;

  gc_init (&gc);
  argv_init (&argv);

  network = print_in6_addr_netbits_only( r6->network, r6->netbits, &gc);
  gateway = print_in6_addr( r6->gateway, 0, &gc);

  if ( !tt->ipv6 )
    {
      msg( M_INFO, "delete_route_ipv6(): not deleting %s/%d, no IPv6 on if %s",
		    network, r6->netbits, device );
      return;
    }

  msg( M_INFO, "delete_route_ipv6(%s/%d)", network, r6->netbits );

  /* if we used a gateway on "add route", we also need to specify it on
   * delete, otherwise some OSes will refuse to delete the route
   */
  if ( tt->type == DEV_TYPE_TAP &&
                  !(r6->metric_defined && r6->metric == 0 ) )
    {
      gateway_needed = true;
    }


#if defined(TARGET_LINUX)
#ifdef ENABLE_IPROUTE
  argv_printf (&argv, "%s -6 route del %s/%d dev %s",
  	      iproute_path,
	      network,
	      r6->netbits,
	      device);
  if (gateway_needed)
    argv_printf_cat (&argv, "via %s", gateway);
#else
  argv_printf (&argv, "%s -A inet6 del %s/%d dev %s",
		ROUTE_PATH,
	      network,
	      r6->netbits,
	      device);
  if (gateway_needed)
    argv_printf_cat (&argv, "gw %s", gateway);
  if (r6->metric_defined && r6->metric > 0 )
    argv_printf_cat (&argv, " metric %d", r6->metric);
#endif  /*ENABLE_IPROUTE*/
  argv_msg (D_ROUTE, &argv);
  openvpn_execve_check (&argv, es, 0, "ERROR: Linux route -6/-A inet6 del command failed");

#elif defined (WIN32)

  /* netsh interface ipv6 delete route 2001:db8::/32 MyTunDevice */
  argv_printf (&argv, "%s%sc interface ipv6 delete route %s/%d %s",
	       get_win_sys_path(),
	       NETSH_PATH_SUFFIX,
	       network,
	       r6->netbits,
	       device);

  /* next-hop depends on TUN or TAP mode:
   * - in TAP mode, we use the "real" next-hop
   * - in TUN mode we use a special-case link-local address that the tapdrvr
   *   knows about and will answer ND (neighbor discovery) packets for
   * (and "route deletion without specifying next-hop" does not work...)
   */
  if ( tt->type == DEV_TYPE_TUN )
	argv_printf_cat( &argv, " %s", "fe80::8" );
  else
	argv_printf_cat( &argv, " %s", gateway );

#if 0
  if (r->metric_defined)
    argv_printf_cat (&argv, "METRIC %d", r->metric);
#endif

  argv_msg (D_ROUTE, &argv);

  netcmd_semaphore_lock ();
  openvpn_execve_check (&argv, es, 0, "ERROR: Windows route add ipv6 command failed");
  netcmd_semaphore_release ();

#elif defined (TARGET_SOLARIS)

  /* example: route delete -inet6 2001:db8::/32 somegateway */
  /* GERT-TODO: this is untested, but should work */

  argv_printf (&argv, "%s delete -inet6 %s/%d %s",
		ROUTE_PATH,
		network,
		r6->netbits,
		gateway );

  argv_msg (D_ROUTE, &argv);
  openvpn_execve_check (&argv, es, 0, "ERROR: Solaris route delete -inet6 command failed");

#elif defined(TARGET_FREEBSD) || defined(TARGET_DRAGONFLY)

  argv_printf (&argv, "%s delete -inet6 %s/%d",
		ROUTE_PATH,
	        network,
	        r6->netbits );

  if (gateway_needed)
    argv_printf_cat (&argv, "%s", gateway);
  else
    argv_printf_cat (&argv, "-iface %s", device);

  argv_msg (D_ROUTE, &argv);
  openvpn_execve_check (&argv, es, 0, "ERROR: *BSD route delete -inet6 command failed");

#elif defined(TARGET_DARWIN) 

  argv_printf (&argv, "%s delete -inet6 %s -prefixlen %d",
		ROUTE_PATH, 
		network, r6->netbits );

  if (gateway_needed)
    argv_printf_cat (&argv, "%s", gateway);
  else
    argv_printf_cat (&argv, "-iface %s", device);

  argv_msg (D_ROUTE, &argv);
  openvpn_execve_check (&argv, es, 0, "ERROR: MacOS X route delete -inet6 command failed");

#elif defined(TARGET_OPENBSD)

  argv_printf (&argv, "%s delete -inet6 %s -prefixlen %d %s",
		ROUTE_PATH,
	        network, r6->netbits, gateway );

  argv_msg (D_ROUTE, &argv);
  openvpn_execve_check (&argv, es, 0, "ERROR: OpenBSD route delete -inet6 command failed");

#elif defined(TARGET_NETBSD)

  argv_printf (&argv, "%s delete -inet6 %s/%d %s",
		ROUTE_PATH,
	        network, r6->netbits, gateway );

  argv_msg (D_ROUTE, &argv);
  openvpn_execve_check (&argv, es, 0, "ERROR: NetBSD route delete -inet6 command failed");

#else
  msg (M_FATAL, "Sorry, but I don't know how to do 'route ipv6' commands on this operating system.  Try putting your routes in a --route-down script");
#endif

  argv_reset (&argv);
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
  DWORD i = adapter_index_of_ip (adapters, gateway, &count, NULL);
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

	  if ((rl->flags & RG_ENABLE) && (rl->spec.flags & RTSA_REMOTE_ENDPOINT))
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

static const MIB_IPFORWARDROW *
get_default_gateway_row (const MIB_IPFORWARDTABLE *routes)
{
  struct gc_arena gc = gc_new ();
  DWORD lowest_metric = MAXDWORD;
  const MIB_IPFORWARDROW *ret = NULL;
  int i;
  int best = -1;

  if (routes)
    {
      for (i = 0; i < routes->dwNumEntries; ++i)
	{
	  const MIB_IPFORWARDROW *row = &routes->table[i];
	  const in_addr_t net = ntohl (row->dwForwardDest);
	  const in_addr_t mask = ntohl (row->dwForwardMask);
	  const DWORD index = row->dwForwardIfIndex;
	  const DWORD metric = row->dwForwardMetric1;

	  dmsg (D_ROUTE_DEBUG, "GDGR: route[%d] %s/%s i=%d m=%d",
		i,
		print_in_addr_t ((in_addr_t) net, 0, &gc),
		print_in_addr_t ((in_addr_t) mask, 0, &gc),
		(int)index,
		(int)metric);

	  if (!net && !mask && metric < lowest_metric)
	    {
	      ret = row;
	      lowest_metric = metric;
	      best = i;
	    }
	}
    }

  dmsg (D_ROUTE_DEBUG, "GDGR: best=%d lm=%u", best, (unsigned int)lowest_metric);

  gc_free (&gc);
  return ret;
}

void
get_default_gateway (struct route_gateway_info *rgi)
{
  struct gc_arena gc = gc_new ();

  const IP_ADAPTER_INFO *adapters = get_adapter_info_list (&gc);
  const MIB_IPFORWARDTABLE *routes = get_windows_routing_table (&gc);
  const MIB_IPFORWARDROW *row = get_default_gateway_row (routes);
  DWORD a_index;
  const IP_ADAPTER_INFO *ai;

  CLEAR(*rgi);

  if (row)
    {
      rgi->gateway.addr = ntohl (row->dwForwardNextHop);
      if (rgi->gateway.addr)
	{
	  rgi->flags |= RGI_ADDR_DEFINED;
	  a_index = adapter_index_of_ip (adapters, rgi->gateway.addr, NULL, &rgi->gateway.netmask);
	  if (a_index != TUN_ADAPTER_INDEX_INVALID)
	    {
	      rgi->adapter_index = a_index;
	      rgi->flags |= (RGI_IFACE_DEFINED|RGI_NETMASK_DEFINED);
	      ai = get_adapter (adapters, a_index);
	      if (ai)
		{
		  memcpy (rgi->hwaddr, ai->Address, 6);
		  rgi->flags |= RGI_HWADDR_DEFINED;
		}
	    }
	}
    }

  gc_free (&gc);
}

static DWORD
windows_route_find_if_index (const struct route *r, const struct tuntap *tt)
{
  struct gc_arena gc = gc_new ();
  DWORD ret = TUN_ADAPTER_INDEX_INVALID;
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
      ret = TUN_ADAPTER_INDEX_INVALID;
    }
  else if (count > 1)
    {
      msg (M_WARN, "Warning: route gateway is ambiguous: %s (%d matches)",
	   print_in_addr_t (r->gateway, 0, &gc),
	   count);
      ret = TUN_ADAPTER_INDEX_INVALID;
    }

  dmsg (D_ROUTE_DEBUG, "DEBUG: route find if: on_tun=%d count=%d index=%d",
       on_tun,
       count,
       (int)ret);

  gc_free (&gc);
  return ret;
}

bool
add_route_ipapi (const struct route *r, const struct tuntap *tt, DWORD adapter_index)
{
  struct gc_arena gc = gc_new ();
  bool ret = false;
  DWORD status;
  const DWORD if_index = (adapter_index == TUN_ADAPTER_INDEX_INVALID) ? windows_route_find_if_index (r, tt) : adapter_index;

  if (if_index != TUN_ADAPTER_INDEX_INVALID)
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
      fr.dwForwardMetric1 = (r->flags & RT_METRIC_DEFINED) ? r->metric : 1;
      fr.dwForwardMetric2 = METRIC_NOT_USED;
      fr.dwForwardMetric3 = METRIC_NOT_USED;
      fr.dwForwardMetric4 = METRIC_NOT_USED;
      fr.dwForwardMetric5 = METRIC_NOT_USED;

      if ((r->network & r->netmask) != r->network)
	msg (M_WARN, "Warning: address %s is not a network address in relation to netmask %s",
	     print_in_addr_t (r->network, 0, &gc),
	     print_in_addr_t (r->netmask, 0, &gc));

      status = CreateIpForwardEntry (&fr);

      if (status == NO_ERROR)
	ret = true;
      else
	{
	  /* failed, try increasing the metric to work around Vista issue */
	  const unsigned int forward_metric_limit = 2048; /* iteratively retry higher metrics up to this limit */

	  for ( ; fr.dwForwardMetric1 <= forward_metric_limit; ++fr.dwForwardMetric1)
	    {
	      /* try a different forward type=3 ("the next hop is the final dest") in addition to 4.
		 --redirect-gateway over RRAS seems to need this. */
	      for (fr.dwForwardType = 4; fr.dwForwardType >= 3; --fr.dwForwardType)
		{
		  status = CreateIpForwardEntry (&fr);
		  if (status == NO_ERROR)
		    {
		      msg (D_ROUTE, "ROUTE: CreateIpForwardEntry succeeded with dwForwardMetric1=%u and dwForwardType=%u",
			   (unsigned int)fr.dwForwardMetric1,
			   (unsigned int)fr.dwForwardType);
		      ret = true;
		      goto doublebreak;
		    }
		  else if (status != ERROR_BAD_ARGUMENTS)
		    goto doublebreak;
		}
	    }

	doublebreak:
	  if (status != NO_ERROR)
	    msg (M_WARN, "ROUTE: route addition failed using CreateIpForwardEntry: %s [status=%u if_index=%u]",
		 strerror_win32 (status, &gc),
		 (unsigned int)status,
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

  if (if_index != TUN_ADAPTER_INDEX_INVALID)
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

void
get_default_gateway (struct route_gateway_info *rgi)
{
  struct gc_arena gc = gc_new ();
  int sd = -1;
  char best_name[16];
  best_name[0] = 0;

  CLEAR(*rgi);

  /* get default gateway IP addr */
  {
    FILE *fp = fopen ("/proc/net/route", "r");
    if (fp)
      {
	char line[256];
	int count = 0;
	unsigned int lowest_metric = UINT_MAX;
	in_addr_t best_gw = 0;
	bool found = false;
	while (fgets (line, sizeof (line), fp) != NULL)
	  {
	    if (count)
	      {
		unsigned int net_x = 0;
		unsigned int mask_x = 0;
		unsigned int gw_x = 0;
		unsigned int metric = 0;
		unsigned int flags = 0;
		char name[16];
		name[0] = 0;
		const int np = sscanf (line, "%15s\t%x\t%x\t%x\t%*s\t%*s\t%d\t%x",
				       name,
				       &net_x,
				       &gw_x,
				       &flags,
				       &metric,
				       &mask_x);
		if (np == 6 && (flags & IFF_UP))
		  {
		    const in_addr_t net = ntohl (net_x);
		    const in_addr_t mask = ntohl (mask_x);
		    const in_addr_t gw = ntohl (gw_x);

		    if (!net && !mask && metric < lowest_metric)
		      {
			found = true;
			best_gw = gw;
			strcpy (best_name, name);
			lowest_metric = metric;
		      }
		  }
	      }
	    ++count;
	  }
	fclose (fp);

	if (found)
	  {
	    rgi->gateway.addr = best_gw;
	    rgi->flags |= RGI_ADDR_DEFINED;
	    if (!rgi->gateway.addr && best_name[0])
	      rgi->flags |= RGI_ON_LINK;
	  }
      }
  }

  /* scan adapter list */
  if (rgi->flags & RGI_ADDR_DEFINED)
    {
      struct ifreq *ifr, *ifend;
      in_addr_t addr, netmask;
      struct ifreq ifreq;
      struct ifconf ifc;
      struct ifreq ifs[20]; /* Maximum number of interfaces to scan */

      if ((sd = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
	{
	  msg (M_WARN, "GDG: socket() failed");
	  goto done;
	}
      ifc.ifc_len = sizeof (ifs);
      ifc.ifc_req = ifs;
      if (ioctl (sd, SIOCGIFCONF, &ifc) < 0)
	{
	  msg (M_WARN, "GDG: ioctl(SIOCGIFCONF) failed");
	  goto done;
	}

      /* scan through interface list */
      ifend = ifs + (ifc.ifc_len / sizeof (struct ifreq));
      for (ifr = ifc.ifc_req; ifr < ifend; ifr++)
	{
	  if (ifr->ifr_addr.sa_family == AF_INET)
	    {
	      /* get interface addr */
	      addr = ntohl(((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr.s_addr);

	      /* get interface name */
	      strncpynt (ifreq.ifr_name, ifr->ifr_name, sizeof (ifreq.ifr_name));

	      /* check that the interface is up */
	      if (ioctl (sd, SIOCGIFFLAGS, &ifreq) < 0)
		continue;
	      if (!(ifreq.ifr_flags & IFF_UP))
		continue;

	      if (rgi->flags & RGI_ON_LINK)
		{
		  /* check that interface name of current interface
		     matches interface name of best default route */
		  if (strcmp(ifreq.ifr_name, best_name))
		    continue;
#if 0
		  /* if point-to-point link, use remote addr as route gateway */
		  if ((ifreq.ifr_flags & IFF_POINTOPOINT) && ioctl (sd, SIOCGIFDSTADDR, &ifreq) >= 0)
		    {
		      rgi->gateway.addr = ntohl(((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr.s_addr);
		      if (rgi->gateway.addr)
			rgi->flags &= ~RGI_ON_LINK;
		    }
#endif
		}
	      else
		{
		  /* get interface netmask */
		  if (ioctl (sd, SIOCGIFNETMASK, &ifreq) < 0)
		    continue;
		  netmask = ntohl(((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr.s_addr);

		  /* check that interface matches default route */
		  if (((rgi->gateway.addr ^ addr) & netmask) != 0)
		    continue;

		  /* save netmask */
		  rgi->gateway.netmask = netmask;
		  rgi->flags |= RGI_NETMASK_DEFINED;
		}

	      /* save iface name */
	      strncpynt (rgi->iface, ifreq.ifr_name, sizeof(rgi->iface));
	      rgi->flags |= RGI_IFACE_DEFINED;

	      /* now get the hardware address. */
	      memset (&ifreq.ifr_hwaddr, 0, sizeof (struct sockaddr));
	      if (ioctl (sd, SIOCGIFHWADDR, &ifreq) < 0)
		{
		  msg (M_WARN, "GDG: SIOCGIFHWADDR(%s) failed", ifreq.ifr_name);
		  goto done;
		}
	      memcpy (rgi->hwaddr, &ifreq.ifr_hwaddr.sa_data, 6);
	      rgi->flags |= RGI_HWADDR_DEFINED;

	      break;
	    }
	}
    }

 done:
  if (sd >= 0)
    close (sd);
  gc_free (&gc);
}

#elif defined(TARGET_FREEBSD)||defined(TARGET_DRAGONFLY)

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

/*
 * FIXME -- add support for netmask, hwaddr, and iface
 */
void
get_default_gateway (struct route_gateway_info *rgi)
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

  CLEAR(*rgi);

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
      msg(M_WARN|M_ERRNO, "Could not retrieve default gateway from route socket:");
      gc_free (&gc);
      close(s);
      return;
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
      return;
    }


  if (gate != NULL )
    {
      rgi->gateway.addr = ntohl(((struct sockaddr_in *)gate)->sin_addr.s_addr);
      rgi->flags |= RGI_ADDR_DEFINED;

      gc_free (&gc);
    }
  else
    {
      gc_free (&gc);
    }
}

#elif defined(TARGET_DARWIN)

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if_dl.h>

struct rtmsg {
  struct rt_msghdr m_rtm;
  char       m_space[512];
};

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

#define NEXTADDR(w, u) \
        if (rtm_addrs & (w)) {\
            l = ROUNDUP(u.sa_len); memmove(cp, &(u), l); cp += l;\
        }

#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

#define max(a,b) ((a) > (b) ? (a) : (b))

void
get_default_gateway (struct route_gateway_info *rgi)
{
  struct gc_arena gc = gc_new ();
  struct rtmsg m_rtmsg;
  int sockfd = -1;
  int seq, l, pid, rtm_addrs, i;
  struct sockaddr so_dst, so_mask;
  char *cp = m_rtmsg.m_space; 
  struct sockaddr *gate = NULL, *ifp = NULL, *sa;
  struct  rt_msghdr *rtm_aux;

# define rtm m_rtmsg.m_rtm

  CLEAR(*rgi);

  /* setup data to send to routing socket */
  pid = getpid();
  seq = 0;
  rtm_addrs = RTA_DST | RTA_NETMASK | RTA_IFP;

  bzero(&m_rtmsg, sizeof(m_rtmsg));
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

  /* transact with routing socket */
  sockfd = socket(PF_ROUTE, SOCK_RAW, 0);
  if (sockfd < 0)
    {
      msg (M_WARN, "GDG: socket #1 failed");
      goto done;
    }
  if (write(sockfd, (char *)&m_rtmsg, l) < 0)
    {
      msg (M_WARN, "GDG: problem writing to routing socket");
      goto done;
    }
  do {
    l = read(sockfd, (char *)&m_rtmsg, sizeof(m_rtmsg));
  } while (l > 0 && (rtm.rtm_seq != seq || rtm.rtm_pid != pid));
  close(sockfd);
  sockfd = -1;

  /* extract return data from routing socket */
  rtm_aux = &rtm;
  cp = ((char *)(rtm_aux + 1));
  if (rtm_aux->rtm_addrs)
    {
      for (i = 1; i; i <<= 1)
	{
	  if (i & rtm_aux->rtm_addrs)
	    {
	      sa = (struct sockaddr *)cp;
	      if (i == RTA_GATEWAY )
		gate = sa;
	      else if (i == RTA_IFP)
		ifp = sa;
	      ADVANCE(cp, sa);
	    }
	}
    }
  else
    goto done;

  /* get gateway addr and interface name */
  if (gate != NULL )
    {
      /* get default gateway addr */
      rgi->gateway.addr = ntohl(((struct sockaddr_in *)gate)->sin_addr.s_addr);
      if (rgi->gateway.addr)
	  rgi->flags |= RGI_ADDR_DEFINED;

      if (ifp)
	{
	  /* get interface name */
	  const struct sockaddr_dl *adl = (struct sockaddr_dl *) ifp;
	  int len = adl->sdl_nlen;
	  if (adl->sdl_nlen && adl->sdl_nlen < sizeof(rgi->iface))
	    {
	      memcpy (rgi->iface, adl->sdl_data, adl->sdl_nlen);
	      rgi->iface[adl->sdl_nlen] = '\0';
	      rgi->flags |= RGI_IFACE_DEFINED;
	    }
	}
    }

  /* get netmask of interface that owns default gateway */
  if (rgi->flags & RGI_IFACE_DEFINED) {
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
      {
	msg (M_WARN, "GDG: socket #2 failed");
	goto done;
      }

    CLEAR(ifr);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpynt(ifr.ifr_name, rgi->iface, IFNAMSIZ);

    if (ioctl(sockfd, SIOCGIFNETMASK, (char *)&ifr) < 0)
      {
	msg (M_WARN, "GDG: ioctl #1 failed");
	goto done;
      }
    close(sockfd);
    sockfd = -1;

    rgi->gateway.netmask = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
    rgi->flags |= RGI_NETMASK_DEFINED;
  }

  /* try to read MAC addr associated with interface that owns default gateway */
  if (rgi->flags & RGI_IFACE_DEFINED)
    {
      struct ifconf ifc;
      struct ifreq *ifr;
      const int bufsize = 4096;
      char *buffer;

      buffer = (char *) gc_malloc (bufsize, true, &gc);
      sockfd = socket(AF_INET, SOCK_DGRAM, 0);
      if (sockfd < 0)
	{
	  msg (M_WARN, "GDG: socket #3 failed");
	  goto done;
	}

      ifc.ifc_len = bufsize;
      ifc.ifc_buf = buffer;

      if (ioctl(sockfd, SIOCGIFCONF, (char *)&ifc) < 0)
	{
	  msg (M_WARN, "GDG: ioctl #2 failed");
	  goto done;
	}
      close(sockfd);
      sockfd = -1;

      for (cp = buffer; cp <= buffer + ifc.ifc_len - sizeof(struct ifreq); )
	{
	  ifr = (struct ifreq *)cp;
	  const size_t len = sizeof(ifr->ifr_name) + max(sizeof(ifr->ifr_addr), ifr->ifr_addr.sa_len);
	  if (!ifr->ifr_addr.sa_family)
	    break;
	  if (!strncmp(ifr->ifr_name, rgi->iface, IFNAMSIZ))
	    {
	      if (ifr->ifr_addr.sa_family == AF_LINK)
		{
		  struct sockaddr_dl *sdl = (struct sockaddr_dl *)&ifr->ifr_addr;
		  memcpy(rgi->hwaddr, LLADDR(sdl), 6);
		  rgi->flags |= RGI_HWADDR_DEFINED;
		}
	    }
	  cp += len;
	}
    }

 done:
  if (sockfd >= 0)
    close(sockfd);
  gc_free (&gc);
}

#undef max

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

/*
 * FIXME -- add support for netmask, hwaddr, and iface
 */
void
get_default_gateway (struct route_gateway_info *rgi)
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

  CLEAR(*rgi);

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
      msg(M_WARN|M_ERRNO, "Could not retrieve default gateway from route socket:");
      gc_free (&gc);
      close(s);
      return;
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
      return;
    }


  if (gate != NULL )
    {
      rgi->gateway.addr = ntohl(((struct sockaddr_in *)gate)->sin_addr.s_addr);
      rgi->flags |= RGI_ADDR_DEFINED;

      gc_free (&gc);
    }
  else
    {
      gc_free (&gc);
    }
}

#else

/*
 * This is a platform-specific method that returns data about
 * the current default gateway.  Return data is placed into
 * a struct route_gateway_info object provided by caller.  The
 * implementation should CLEAR the structure before adding
 * data to it.
 *
 * Data returned includes:
 * 1. default gateway address (rgi->gateway.addr)
 * 2. netmask of interface that owns default gateway
 *    (rgi->gateway.netmask)
 * 3. hardware address (i.e. MAC address) of interface that owns
 *    default gateway (rgi->hwaddr)
 * 4. interface name (or adapter index on Windows) that owns default
 *    gateway (rgi->iface or rgi->adapter_index)
 * 5. an array of additional address/netmask pairs defined by
 *    interface that owns default gateway (rgi->addrs with length
 *    given in rgi->n_addrs)
 *
 * The flags RGI_x_DEFINED may be used to indicate which of the data
 * members were successfully returned (set in rgi->flags).  All of
 * the data members are optional, however certain OpenVPN functionality
 * may be disabled by missing items.
 */
void
get_default_gateway (struct route_gateway_info *rgi)
{
  CLEAR(*rgi);
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

/*
 * get_bypass_addresses() is used by the redirect-gateway bypass-x
 * functions to build a route bypass to selected DHCP/DNS servers,
 * so that outgoing packets to these servers don't end up in the tunnel.
 */

#if defined(WIN32)

static void
add_host_route_if_nonlocal (struct route_bypass *rb, const in_addr_t addr)
{
  if (test_local_addr(addr, NULL) == TLA_NONLOCAL && addr != 0 && addr != IPV4_NETMASK_HOST)
    add_bypass_address (rb, addr);
}

static void
add_host_route_array (struct route_bypass *rb, const IP_ADDR_STRING *iplist)
{
  while (iplist)
    {
      bool succeed = false;
      const in_addr_t ip = getaddr (GETADDR_HOST_ORDER, iplist->IpAddress.String, 0, &succeed, NULL);
      if (succeed)
	{
	  add_host_route_if_nonlocal (rb, ip);
	}
      iplist = iplist->Next;
    }
}

static void
get_bypass_addresses (struct route_bypass *rb, const unsigned int flags)
{
  struct gc_arena gc = gc_new ();
  /*bool ret_bool = false;*/

  /* get full routing table */
  const MIB_IPFORWARDTABLE *routes = get_windows_routing_table (&gc);

  /* get the route which represents the default gateway */
  const MIB_IPFORWARDROW *row = get_default_gateway_row (routes);

  if (row)
    {
      /* get the adapter which the default gateway is associated with */
      const IP_ADAPTER_INFO *dgi = get_adapter_info (row->dwForwardIfIndex, &gc);

      /* get extra adapter info, such as DNS addresses */
      const IP_PER_ADAPTER_INFO *pai = get_per_adapter_info (row->dwForwardIfIndex, &gc);

      /* Bypass DHCP server address */
      if ((flags & RG_BYPASS_DHCP) && dgi && dgi->DhcpEnabled)
	add_host_route_array (rb, &dgi->DhcpServer);

      /* Bypass DNS server addresses */
      if ((flags & RG_BYPASS_DNS) && pai)
	add_host_route_array (rb, &pai->DnsServerList);
    }

  gc_free (&gc);
}

#else

static void
get_bypass_addresses (struct route_bypass *rb, const unsigned int flags)  /* PLATFORM-SPECIFIC */
{
}

#endif

/*
 * Test if addr is reachable via a local interface (return ILA_LOCAL),
 * or if it needs to be routed via the default gateway (return
 * ILA_NONLOCAL).  If the target platform doesn't implement this
 * function, return ILA_NOT_IMPLEMENTED.
 *
 * Used by redirect-gateway autolocal feature
 */

#if defined(WIN32)

int
test_local_addr (const in_addr_t addr, const struct route_gateway_info *rgi)
{
  struct gc_arena gc = gc_new ();
  const in_addr_t nonlocal_netmask = 0x80000000L; /* routes with netmask <= to this are considered non-local */
  bool ret = TLA_NONLOCAL;

  /* get full routing table */
  const MIB_IPFORWARDTABLE *rt = get_windows_routing_table (&gc);
  if (rt)
    {
      int i;
      for (i = 0; i < rt->dwNumEntries; ++i)
	{
	  const MIB_IPFORWARDROW *row = &rt->table[i];
	  const in_addr_t net = ntohl (row->dwForwardDest);
	  const in_addr_t mask = ntohl (row->dwForwardMask);
	  if (mask > nonlocal_netmask && (addr & mask) == net)
	    {
	      ret = TLA_LOCAL;
	      break;
	    }
	}
    }

  gc_free (&gc);
  return ret;
}

#else

int
test_local_addr (const in_addr_t addr, const struct route_gateway_info *rgi) /* PLATFORM-SPECIFIC */
{
  if (rgi)
    {
      if (local_route (addr, 0xFFFFFFFF, rgi->gateway.addr, rgi))
	return TLA_LOCAL;
      else
	return TLA_NONLOCAL;
    }
  return TLA_NOT_IMPLEMENTED;
}

#endif
