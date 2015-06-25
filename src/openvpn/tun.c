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
 * Support routines for configuring and accessing TUN/TAP
 * virtual network adapters.
 *
 * This file is based on the TUN/TAP driver interface routines
 * from VTun by Maxim Krasnyansky <max_mk@yahoo.com>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "tun.h"
#include "fdmisc.h"
#include "common.h"
#include "misc.h"
#include "socket.h"
#include "manage.h"
#include "route.h"
#include "win32.h"

#include "memdbg.h"

#ifdef WIN32

/* #define SIMULATE_DHCP_FAILED */       /* simulate bad DHCP negotiation */

#define NI_TEST_FIRST  (1<<0)
#define NI_IP_NETMASK  (1<<1)
#define NI_OPTIONS     (1<<2)

static void netsh_ifconfig (const struct tuntap_options *to,
			    const char *flex_name,
			    const in_addr_t ip,
			    const in_addr_t netmask,
			    const unsigned int flags);
static void netsh_command (const struct argv *a, int n);

static const char *netsh_get_id (const char *dev_node, struct gc_arena *gc);

#endif

#ifdef TARGET_SOLARIS
static void solaris_error_close (struct tuntap *tt, const struct env_set *es, const char *actual, bool unplumb_inet6);
#include <stropts.h>
#endif

#if defined(TARGET_DARWIN) && HAVE_NET_IF_UTUN_H
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <sys/sys_domain.h>
#endif

static void clear_tuntap (struct tuntap *tuntap);

bool
is_dev_type (const char *dev, const char *dev_type, const char *match_type)
{
  ASSERT (match_type);
  if (!dev)
    return false;
  if (dev_type)
    return !strcmp (dev_type, match_type);
  else
    return !strncmp (dev, match_type, strlen (match_type));
}

int
dev_type_enum (const char *dev, const char *dev_type)
{
  if (is_dev_type (dev, dev_type, "tun"))
    return DEV_TYPE_TUN;
  else if (is_dev_type (dev, dev_type, "tap"))
    return DEV_TYPE_TAP;
  else if (is_dev_type (dev, dev_type, "null"))
    return DEV_TYPE_NULL;
  else
    return DEV_TYPE_UNDEF;
}

const char *
dev_type_string (const char *dev, const char *dev_type)
{
  switch (dev_type_enum (dev, dev_type))
    {
    case DEV_TYPE_TUN:
      return "tun";
    case DEV_TYPE_TAP:
      return "tap";
    case DEV_TYPE_NULL:
      return "null";
    default:
      return "[unknown-dev-type]";
    }
}

/*
 * Try to predict the actual TUN/TAP device instance name,
 * before the device is actually opened.
 */
const char *
guess_tuntap_dev (const char *dev,
		  const char *dev_type,
		  const char *dev_node,
		  struct gc_arena *gc)
{
#ifdef WIN32
  const int dt = dev_type_enum (dev, dev_type);
  if (dt == DEV_TYPE_TUN || dt == DEV_TYPE_TAP)
    {
      return netsh_get_id (dev_node, gc);
    }
#endif

  /* default case */
  return dev;
}


/* --ifconfig-nowarn disables some options sanity checking */
static const char ifconfig_warn_how_to_silence[] = "(silence this warning with --ifconfig-nowarn)";

/*
 * If !tun, make sure ifconfig_remote_netmask looks
 *  like a netmask.
 *
 * If tun, make sure ifconfig_remote_netmask looks
 *  like an IPv4 address.
 */
static void
ifconfig_sanity_check (bool tun, in_addr_t addr, int topology)
{
  struct gc_arena gc = gc_new ();
  const bool looks_like_netmask = ((addr & 0xFF000000) == 0xFF000000);
  if (tun)
    {
      if (looks_like_netmask && (topology == TOP_NET30 || topology == TOP_P2P))
	msg (M_WARN, "WARNING: Since you are using --dev tun with a point-to-point topology, the second argument to --ifconfig must be an IP address.  You are using something (%s) that looks more like a netmask. %s",
	     print_in_addr_t (addr, 0, &gc),
	     ifconfig_warn_how_to_silence);
    }
  else /* tap */
    {
      if (!looks_like_netmask)
	msg (M_WARN, "WARNING: Since you are using --dev tap, the second argument to --ifconfig must be a netmask, for example something like 255.255.255.0. %s",
	     ifconfig_warn_how_to_silence);
    }
  gc_free (&gc);
}

/*
 * For TAP-style devices, generate a broadcast address.
 */
static in_addr_t
generate_ifconfig_broadcast_addr (in_addr_t local,
				  in_addr_t netmask)
{
  return local | ~netmask;
}

/*
 * Check that --local and --remote addresses do not
 * clash with ifconfig addresses or subnet.
 */
static void
check_addr_clash (const char *name,
		  int type,
		  in_addr_t public,
		  in_addr_t local,
		  in_addr_t remote_netmask)
{
  struct gc_arena gc = gc_new ();
#if 0
  msg (M_INFO, "CHECK_ADDR_CLASH type=%d public=%s local=%s, remote_netmask=%s",
       type,
       print_in_addr_t (public, 0, &gc),
       print_in_addr_t (local, 0, &gc),
       print_in_addr_t (remote_netmask, 0, &gc));
#endif

  if (public)
    {
      if (type == DEV_TYPE_TUN)
	{
	  const in_addr_t test_netmask = 0xFFFFFF00;
	  const in_addr_t public_net = public & test_netmask;
	  const in_addr_t local_net = local & test_netmask;
	  const in_addr_t remote_net = remote_netmask & test_netmask;

	  if (public == local || public == remote_netmask)
	    msg (M_WARN,
		 "WARNING: --%s address [%s] conflicts with --ifconfig address pair [%s, %s]. %s",
		 name,
		 print_in_addr_t (public, 0, &gc),
		 print_in_addr_t (local, 0, &gc),
		 print_in_addr_t (remote_netmask, 0, &gc),
		 ifconfig_warn_how_to_silence);

	  if (public_net == local_net || public_net == remote_net)
	    msg (M_WARN,
		 "WARNING: potential conflict between --%s address [%s] and --ifconfig address pair [%s, %s] -- this is a warning only that is triggered when local/remote addresses exist within the same /24 subnet as --ifconfig endpoints. %s",
		 name,
		 print_in_addr_t (public, 0, &gc),
		 print_in_addr_t (local, 0, &gc),
		 print_in_addr_t (remote_netmask, 0, &gc),
		 ifconfig_warn_how_to_silence);
	}
      else if (type == DEV_TYPE_TAP)
	{
	  const in_addr_t public_network = public & remote_netmask;
	  const in_addr_t virtual_network = local & remote_netmask;
	  if (public_network == virtual_network)
	    msg (M_WARN,
		 "WARNING: --%s address [%s] conflicts with --ifconfig subnet [%s, %s] -- local and remote addresses cannot be inside of the --ifconfig subnet. %s",
		 name,
		 print_in_addr_t (public, 0, &gc),
		 print_in_addr_t (local, 0, &gc),
		 print_in_addr_t (remote_netmask, 0, &gc),
		 ifconfig_warn_how_to_silence);
	}
    }
  gc_free (&gc);
}

/*
 * Issue a warning if ip/netmask (on the virtual IP network) conflicts with
 * the settings on the local LAN.  This is designed to flag issues where
 * (for example) the OpenVPN server LAN is running on 192.168.1.x, but then
 * an OpenVPN client tries to connect from a public location that is also running
 * off of a router set to 192.168.1.x.
 */
void
check_subnet_conflict (const in_addr_t ip,
		       const in_addr_t netmask,
		       const char *prefix)
{
#if 0 /* too many false positives */
  struct gc_arena gc = gc_new ();
  in_addr_t lan_gw = 0;
  in_addr_t lan_netmask = 0;

  if (get_default_gateway (&lan_gw, &lan_netmask) && lan_netmask)
    {
      const in_addr_t lan_network = lan_gw & lan_netmask; 
      const in_addr_t network = ip & netmask;

      /* do the two subnets defined by network/netmask and lan_network/lan_netmask intersect? */
      if ((network & lan_netmask) == lan_network
	  || (lan_network & netmask) == network)
	{
	  msg (M_WARN, "WARNING: potential %s subnet conflict between local LAN [%s/%s] and remote VPN [%s/%s]",
	       prefix,
	       print_in_addr_t (lan_network, 0, &gc),
	       print_in_addr_t (lan_netmask, 0, &gc),
	       print_in_addr_t (network, 0, &gc),
	       print_in_addr_t (netmask, 0, &gc));
	}
    }
  gc_free (&gc);
#endif
}

void
warn_on_use_of_common_subnets (void)
{
  struct gc_arena gc = gc_new ();
  struct route_gateway_info rgi;
  const int needed = (RGI_ADDR_DEFINED|RGI_NETMASK_DEFINED);

  get_default_gateway (&rgi);
  if ((rgi.flags & needed) == needed)
    {
      const in_addr_t lan_network = rgi.gateway.addr & rgi.gateway.netmask;
      if (lan_network == 0xC0A80000 || lan_network == 0xC0A80100)
	msg (M_WARN, "NOTE: your local LAN uses the extremely common subnet address 192.168.0.x or 192.168.1.x.  Be aware that this might create routing conflicts if you connect to the VPN server from public locations such as internet cafes that use the same subnet.");
    }
  gc_free (&gc);
}

/*
 * Return a string to be used for options compatibility check
 * between peers.
 */
const char *
ifconfig_options_string (const struct tuntap* tt, bool remote, bool disable, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (256, gc);
  if (tt->did_ifconfig_setup && !disable)
    {
      if (tt->type == DEV_TYPE_TAP || (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET))
	{
	  buf_printf (&out, "%s %s",
		      print_in_addr_t (tt->local & tt->remote_netmask, 0, gc),
		      print_in_addr_t (tt->remote_netmask, 0, gc));
	}
      else if (tt->type == DEV_TYPE_TUN)
	{
	  const char *l, *r;
	  if (remote)
	    {
	      r = print_in_addr_t (tt->local, 0, gc);
	      l = print_in_addr_t (tt->remote_netmask, 0, gc);
	    }
	  else
	    {
	      l = print_in_addr_t (tt->local, 0, gc);
	      r = print_in_addr_t (tt->remote_netmask, 0, gc);
	    }
	  buf_printf (&out, "%s %s", r, l);
	}
      else
	buf_printf (&out, "[undef]");
    }
  return BSTR (&out);
}

/*
 * Return a status string describing wait state.
 */
const char *
tun_stat (const struct tuntap *tt, unsigned int rwflags, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (64, gc);
  if (tt)
    {
      if (rwflags & EVENT_READ)
	{
	  buf_printf (&out, "T%s",
		      (tt->rwflags_debug & EVENT_READ) ? "R" : "r");
#ifdef WIN32
	  buf_printf (&out, "%s",
		      overlapped_io_state_ascii (&tt->reads));
#endif
	}
      if (rwflags & EVENT_WRITE)
	{
	  buf_printf (&out, "T%s",
		      (tt->rwflags_debug & EVENT_WRITE) ? "W" : "w");
#ifdef WIN32
	  buf_printf (&out, "%s",
		      overlapped_io_state_ascii (&tt->writes));
#endif
	}
    }
  else
    {
      buf_printf (&out, "T?");
    }
  return BSTR (&out);
}

/*
 * Return true for point-to-point topology, false for subnet topology
 */
bool
is_tun_p2p (const struct tuntap *tt)
{
  bool tun = false;

  if (tt->type == DEV_TYPE_TAP || (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET))
    tun = false;
  else if (tt->type == DEV_TYPE_TUN)
    tun = true;
  else
    msg (M_FATAL, "Error: problem with tun vs. tap setting"); /* JYFIXME -- needs to be caught earlier, in init_tun? */

  return tun;
}

/*
 * Set the ifconfig_* environment variables, both for IPv4 and IPv6
 */
void
do_ifconfig_setenv (const struct tuntap *tt, struct env_set *es)
{
    struct gc_arena gc = gc_new ();
    const char *ifconfig_local = print_in_addr_t (tt->local, 0, &gc);
    const char *ifconfig_remote_netmask = print_in_addr_t (tt->remote_netmask, 0, &gc);

    /*
     * Set environmental variables with ifconfig parameters.
     */
    if (tt->did_ifconfig_setup)
    {
	bool tun = is_tun_p2p (tt);

	setenv_str (es, "ifconfig_local", ifconfig_local);
	if (tun)
	{
	    setenv_str (es, "ifconfig_remote", ifconfig_remote_netmask);
	}
	else
	{
	    const char *ifconfig_broadcast = print_in_addr_t (tt->broadcast, 0, &gc);
	    setenv_str (es, "ifconfig_netmask", ifconfig_remote_netmask);
	    setenv_str (es, "ifconfig_broadcast", ifconfig_broadcast);
	}
    }

    if (tt->did_ifconfig_ipv6_setup)
    {
	const char *ifconfig_ipv6_local = print_in6_addr (tt->local_ipv6, 0, &gc);
	const char *ifconfig_ipv6_remote = print_in6_addr (tt->remote_ipv6, 0, &gc);

	setenv_str (es, "ifconfig_ipv6_local", ifconfig_ipv6_local);
	setenv_int (es, "ifconfig_ipv6_netbits", tt->netbits_ipv6);
	setenv_str (es, "ifconfig_ipv6_remote", ifconfig_ipv6_remote);
    }

    gc_free (&gc);
}

/*
 * Init tun/tap object.
 *
 * Set up tuntap structure for ifconfig,
 * but don't execute yet.
 */
struct tuntap *
init_tun (const char *dev,       /* --dev option */
	  const char *dev_type,  /* --dev-type option */
	  int topology,          /* one of the TOP_x values */
	  const char *ifconfig_local_parm,          /* --ifconfig parm 1 */
	  const char *ifconfig_remote_netmask_parm, /* --ifconfig parm 2 */
	  const char *ifconfig_ipv6_local_parm,     /* --ifconfig parm 1 IPv6 */
	  int         ifconfig_ipv6_netbits_parm,
	  const char *ifconfig_ipv6_remote_parm,    /* --ifconfig parm 2 IPv6 */
	  in_addr_t local_public,
	  in_addr_t remote_public,
	  const bool strict_warn,
	  struct env_set *es)
{
  struct gc_arena gc = gc_new ();
  struct tuntap *tt;

  ALLOC_OBJ (tt, struct tuntap);
  clear_tuntap (tt);

  tt->type = dev_type_enum (dev, dev_type);
  tt->topology = topology;

  if (ifconfig_local_parm && ifconfig_remote_netmask_parm)
    {
      bool tun = false;

      /*
       * We only handle TUN/TAP devices here, not --dev null devices.
       */
      tun = is_tun_p2p (tt);

      /*
       * Convert arguments to binary IPv4 addresses.
       */

      tt->local = getaddr (
			   GETADDR_RESOLVE
			   | GETADDR_HOST_ORDER
			   | GETADDR_FATAL_ON_SIGNAL
			   | GETADDR_FATAL,
			   ifconfig_local_parm,
			   0,
			   NULL,
			   NULL);

      tt->remote_netmask = getaddr (
				    (tun ? GETADDR_RESOLVE : 0)
				    | GETADDR_HOST_ORDER
				    | GETADDR_FATAL_ON_SIGNAL
				    | GETADDR_FATAL,
				    ifconfig_remote_netmask_parm,
				    0,
				    NULL,
				    NULL);

      /*
       * Look for common errors in --ifconfig parms
       */
      if (strict_warn)
	{
	  ifconfig_sanity_check (tt->type == DEV_TYPE_TUN, tt->remote_netmask, tt->topology);

	  /*
	   * If local_public or remote_public addresses are defined,
	   * make sure they do not clash with our virtual subnet.
	   */

	  check_addr_clash ("local",
			    tt->type,
			    local_public,
			    tt->local,
			    tt->remote_netmask);

	  check_addr_clash ("remote",
			    tt->type,
			    remote_public,
			    tt->local,
			    tt->remote_netmask);

	  if (tt->type == DEV_TYPE_TAP || (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET))
	    check_subnet_conflict (tt->local, tt->remote_netmask, "TUN/TAP adapter");
	  else if (tt->type == DEV_TYPE_TUN)
	    check_subnet_conflict (tt->local, IPV4_NETMASK_HOST, "TUN/TAP adapter");
	}

      /*
       * If TAP-style interface, generate broadcast address.
       */
      if (!tun)
	{
	  tt->broadcast = generate_ifconfig_broadcast_addr (tt->local, tt->remote_netmask);
	}


      tt->did_ifconfig_setup = true;
    }

  if (ifconfig_ipv6_local_parm && ifconfig_ipv6_remote_parm)
    {

      /*
       * Convert arguments to binary IPv6 addresses.
       */

      if ( inet_pton( AF_INET6, ifconfig_ipv6_local_parm, &tt->local_ipv6 ) != 1 ||
           inet_pton( AF_INET6, ifconfig_ipv6_remote_parm, &tt->remote_ipv6 ) != 1 ) 
	{
	  msg( M_FATAL, "init_tun: problem converting IPv6 ifconfig addresses %s and %s to binary", ifconfig_ipv6_local_parm, ifconfig_ipv6_remote_parm );
	}
      tt->netbits_ipv6 = ifconfig_ipv6_netbits_parm;

      tt->did_ifconfig_ipv6_setup = true;
    }

  /*
   * Set environmental variables with ifconfig parameters.
   */
  if (es) do_ifconfig_setenv(tt, es);

  gc_free (&gc);
  return tt;
}

/*
 * Platform specific tun initializations
 */
void
init_tun_post (struct tuntap *tt,
	       const struct frame *frame,
	       const struct tuntap_options *options)
{
  tt->options = *options;
#ifdef WIN32
  overlapped_io_init (&tt->reads, frame, FALSE, true);
  overlapped_io_init (&tt->writes, frame, TRUE, true);
  tt->rw_handle.read = tt->reads.overlapped.hEvent;
  tt->rw_handle.write = tt->writes.overlapped.hEvent;
  tt->adapter_index = TUN_ADAPTER_INDEX_INVALID;
#endif
}

#if defined(WIN32) || \
    defined(TARGET_DARWIN) || defined(TARGET_NETBSD) || defined(TARGET_OPENBSD)

/* some of the platforms will auto-add a "network route" pointing
 * to the interface on "ifconfig tunX 2001:db8::1/64", others need
 * an extra call to "route add..."
 * -> helper function to simplify code below
 */
void add_route_connected_v6_net(struct tuntap * tt,
	                        const struct env_set *es)
{
    struct route_ipv6 r6;

    r6.defined = true;
    r6.network = tt->local_ipv6;
    r6.netbits = tt->netbits_ipv6;
    r6.gateway = tt->local_ipv6;
    r6.metric  = 0;			/* connected route */
    r6.metric_defined = true;
    add_route_ipv6 (&r6, tt, 0, es);
}

void delete_route_connected_v6_net(struct tuntap * tt,
	                           const struct env_set *es)
{
    struct route_ipv6 r6;

    r6.defined = true;
    r6.network = tt->local_ipv6;
    r6.netbits = tt->netbits_ipv6;
    r6.gateway = tt->local_ipv6;
    r6.metric  = 0;			/* connected route */
    r6.metric_defined = true;
    delete_route_ipv6 (&r6, tt, 0, es);
}
#endif

#if defined(TARGET_FREEBSD)||defined(TARGET_DRAGONFLY)
/* we can't use true subnet mode on tun on all platforms, as that
 * conflicts with IPv6 (wants to use ND then, which we don't do),
 * but the OSes want "a remote address that is different from ours"
 * - so we construct one, normally the first in the subnet, but if
 * this is the same as ours, use the second one.
 * The actual address does not matter at all, as the tun interface
 * is still point to point and no layer 2 resolution is done...
 */

char *
create_arbitrary_remote( struct tuntap *tt, struct gc_arena * gc )
{
  in_addr_t remote;

  remote = (tt->local & tt->remote_netmask) +1;

  if ( remote == tt->local ) remote ++;

  return print_in_addr_t (remote, 0, &gc);
}
#endif

/* execute the ifconfig command through the shell */
void
do_ifconfig (struct tuntap *tt,
	     const char *actual,    /* actual device name */
	     int tun_mtu,
	     const struct env_set *es)
{
  struct gc_arena gc = gc_new ();

  if (tt->did_ifconfig_setup)
    {
      bool tun = false;
      const char *ifconfig_local = NULL;
      const char *ifconfig_remote_netmask = NULL;
      const char *ifconfig_broadcast = NULL;
      const char *ifconfig_ipv6_local = NULL;
      const char *ifconfig_ipv6_remote = NULL;
      bool do_ipv6 = false;
      struct argv argv;

      argv_init (&argv);

      msg( M_INFO, "do_ifconfig, tt->ipv6=%d, tt->did_ifconfig_ipv6_setup=%d",
	           tt->ipv6, tt->did_ifconfig_ipv6_setup );

      /*
       * We only handle TUN/TAP devices here, not --dev null devices.
       */
      tun = is_tun_p2p (tt);

      /*
       * Set ifconfig parameters
       */
      ifconfig_local = print_in_addr_t (tt->local, 0, &gc);
      ifconfig_remote_netmask = print_in_addr_t (tt->remote_netmask, 0, &gc);

      if ( tt->ipv6 && tt->did_ifconfig_ipv6_setup )
        {
	  ifconfig_ipv6_local = print_in6_addr (tt->local_ipv6, 0, &gc);
	  ifconfig_ipv6_remote = print_in6_addr (tt->remote_ipv6, 0, &gc);
	  do_ipv6 = true;
	}

      /*
       * If TAP-style device, generate broadcast address.
       */
      if (!tun)
	ifconfig_broadcast = print_in_addr_t (tt->broadcast, 0, &gc);

#ifdef ENABLE_MANAGEMENT
  if (management)
    {
      management_set_state (management,
			    OPENVPN_STATE_ASSIGN_IP,
			    NULL,
			    tt->local,
			    0);
    }
#endif


#if defined(TARGET_LINUX)
#ifdef ENABLE_IPROUTE
	/*
	 * Set the MTU for the device
	 */
	argv_printf (&argv,
			  "%s link set dev %s up mtu %d",
			  iproute_path,
			  actual,
			  tun_mtu
			  );
	  argv_msg (M_INFO, &argv);
	  openvpn_execve_check (&argv, es, S_FATAL, "Linux ip link set failed");

	if (tun) {

		/*
		 * Set the address for the device
		 */
		argv_printf (&argv,
				  "%s addr add dev %s local %s peer %s",
				  iproute_path,
				  actual,
				  ifconfig_local,
				  ifconfig_remote_netmask
				  );
		  argv_msg (M_INFO, &argv);
		  openvpn_execve_check (&argv, es, S_FATAL, "Linux ip addr add failed");
	} else {
		argv_printf (&argv,
				  "%s addr add dev %s %s/%d broadcast %s",
				  iproute_path,
				  actual,
				  ifconfig_local,
				  count_netmask_bits(ifconfig_remote_netmask),
				  ifconfig_broadcast
				  );
		  argv_msg (M_INFO, &argv);
		  openvpn_execve_check (&argv, es, S_FATAL, "Linux ip addr add failed");
	}
      if ( do_ipv6 )
	{
	  argv_printf( &argv,
		      "%s -6 addr add %s/%d dev %s",
		      iproute_path,
		      ifconfig_ipv6_local,
		      tt->netbits_ipv6,
		      actual
		      );
	  argv_msg (M_INFO, &argv);
	  openvpn_execve_check (&argv, es, S_FATAL, "Linux ip -6 addr add failed");
	}
      tt->did_ifconfig = true;
#else
      if (tun)
	argv_printf (&argv,
			  "%s %s %s pointopoint %s mtu %d",
			  IFCONFIG_PATH,
			  actual,
			  ifconfig_local,
			  ifconfig_remote_netmask,
			  tun_mtu
			  );
      else
	argv_printf (&argv,
			  "%s %s %s netmask %s mtu %d broadcast %s",
			  IFCONFIG_PATH,
			  actual,
			  ifconfig_local,
			  ifconfig_remote_netmask,
			  tun_mtu,
			  ifconfig_broadcast
			  );
      argv_msg (M_INFO, &argv);
      openvpn_execve_check (&argv, es, S_FATAL, "Linux ifconfig failed");
      if ( do_ipv6 )
	{
	  argv_printf (&argv,
			  "%s %s add %s/%d",
			  IFCONFIG_PATH,
			  actual,
			  ifconfig_ipv6_local,
			  tt->netbits_ipv6
			  );
	  argv_msg (M_INFO, &argv);
	  openvpn_execve_check (&argv, es, S_FATAL, "Linux ifconfig inet6 failed");
	}
      tt->did_ifconfig = true;

#endif /*ENABLE_IPROUTE*/
#elif defined(TARGET_SOLARIS)

      /* Solaris 2.6 (and 7?) cannot set all parameters in one go...
       * example:
       *    ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 up
       *    ifconfig tun2 netmask 255.255.255.255
       */
      if (tun)
	{
	  argv_printf (&argv,
			    "%s %s %s %s mtu %d up",
			    IFCONFIG_PATH,
			    actual,
			    ifconfig_local,
			    ifconfig_remote_netmask,
			    tun_mtu
			    );

	  argv_msg (M_INFO, &argv);
	  if (!openvpn_execve_check (&argv, es, 0, "Solaris ifconfig phase-1 failed"))
	    solaris_error_close (tt, es, actual, false);

	  argv_printf (&argv,
			    "%s %s netmask 255.255.255.255",
			    IFCONFIG_PATH,
			    actual
			    );
	}
      else
        if (tt->topology == TOP_SUBNET)
	{
          argv_printf (&argv,
                              "%s %s %s %s netmask %s mtu %d up",
                              IFCONFIG_PATH,
                              actual,
                              ifconfig_local,
                              ifconfig_local,
                              ifconfig_remote_netmask,
                              tun_mtu
                              );
	}
        else
          argv_printf (&argv,
                            " %s %s %s netmask %s broadcast + up",
                            IFCONFIG_PATH,
                            actual,
                            ifconfig_local,
                            ifconfig_remote_netmask
                            );

      argv_msg (M_INFO, &argv);
      if (!openvpn_execve_check (&argv, es, 0, "Solaris ifconfig phase-2 failed"))
	solaris_error_close (tt, es, actual, false);

      if ( do_ipv6 )
        {
 	  argv_printf (&argv, "%s %s inet6 unplumb",
			    IFCONFIG_PATH, actual );
	  argv_msg (M_INFO, &argv);
	  openvpn_execve_check (&argv, es, 0, NULL);

	  if ( tt->type == DEV_TYPE_TUN )
	   {
	      argv_printf (&argv,
			    "%s %s inet6 plumb %s/%d %s up",
			    IFCONFIG_PATH,
			    actual,
			    ifconfig_ipv6_local,
			    tt->netbits_ipv6,
			    ifconfig_ipv6_remote
			    );
	    }
	  else						/* tap mode */
	    {
	      /* base IPv6 tap interface needs to be brought up first
	       */
	      argv_printf (&argv, "%s %s inet6 plumb up",
			    IFCONFIG_PATH, actual );
	      argv_msg (M_INFO, &argv);
	      if (!openvpn_execve_check (&argv, es, 0, "Solaris ifconfig IPv6 (prepare) failed"))
		solaris_error_close (tt, es, actual, true);

	      /* we might need to do "ifconfig %s inet6 auto-dhcp drop"
	       * after the system has noticed the interface and fired up
	       * the DHCPv6 client - but this takes quite a while, and the 
	       * server will ignore the DHCPv6 packets anyway.  So we don't.
	       */

	      /* static IPv6 addresses need to go to a subinterface (tap0:1)
	       */
	      argv_printf (&argv,
			    "%s %s inet6 addif %s/%d up",
			    IFCONFIG_PATH, actual,
			    ifconfig_ipv6_local, tt->netbits_ipv6 );
	    }
	  argv_msg (M_INFO, &argv);
	  if (!openvpn_execve_check (&argv, es, 0, "Solaris ifconfig IPv6 failed"))
	    solaris_error_close (tt, es, actual, true);
        }

      if (!tun && tt->topology == TOP_SUBNET)
	{
	  /* Add a network route for the local tun interface */
	  struct route_ipv4 r;
	  CLEAR (r);      
	  r.flags = RT_DEFINED | RT_METRIC_DEFINED;
	  r.network = tt->local & tt->remote_netmask;
	  r.netmask = tt->remote_netmask;
	  r.gateway = tt->local;  
	  r.metric = 0;
	  add_route (&r, tt, 0, NULL, es);
	}

      tt->did_ifconfig = true;

#elif defined(TARGET_OPENBSD)

      /*
       * On OpenBSD, tun interfaces are persistent if created with
       * "ifconfig tunX create", and auto-destroyed if created by
       * opening "/dev/tunX" (so we just use the /dev/tunX)
       */

      /* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
      if (tun)
	argv_printf (&argv,
			  "%s %s %s %s mtu %d netmask 255.255.255.255 up -link0",
			  IFCONFIG_PATH,
			  actual,
			  ifconfig_local,
			  ifconfig_remote_netmask,
			  tun_mtu
			  );
      else
	if ( tt->topology == TOP_SUBNET )
	{
	    argv_printf (&argv,
			  "%s %s %s %s mtu %d netmask %s up -link0",
			  IFCONFIG_PATH,
			  actual,
			  ifconfig_local,
			  ifconfig_local,
			  tun_mtu,
			  ifconfig_remote_netmask
			  );
	}
      else
	argv_printf (&argv,
			  "%s %s %s netmask %s mtu %d broadcast %s link0",
			  IFCONFIG_PATH,
			  actual,
			  ifconfig_local,
			  ifconfig_remote_netmask,
			  tun_mtu,
			  ifconfig_broadcast
			  );
      argv_msg (M_INFO, &argv);
      openvpn_execve_check (&argv, es, S_FATAL, "OpenBSD ifconfig failed");
      if ( do_ipv6 )
	{
	  argv_printf (&argv,
			  "%s %s inet6 %s/%d",
			  IFCONFIG_PATH,
			  actual,
			  ifconfig_ipv6_local,
			  tt->netbits_ipv6
			  );
	  argv_msg (M_INFO, &argv);
	  openvpn_execve_check (&argv, es, S_FATAL, "OpenBSD ifconfig inet6 failed");

	  /* and, hooray, we explicitely need to add a route... */
	  add_route_connected_v6_net(tt, es);
	}
      tt->did_ifconfig = true;

#elif defined(TARGET_NETBSD)

/* whether or not NetBSD can do IPv6 can be seen by the availability of
 * the TUNSIFHEAD ioctl() - see next TARGET_NETBSD block for more details
 */
#ifdef TUNSIFHEAD
# define NETBSD_MULTI_AF
#endif

      if (tun)
	argv_printf (&argv,
			  "%s %s %s %s mtu %d netmask 255.255.255.255 up",
			  IFCONFIG_PATH,
			  actual,
			  ifconfig_local,
			  ifconfig_remote_netmask,
			  tun_mtu
			  );
      else
	if ( tt->topology == TOP_SUBNET )
	{
	    argv_printf (&argv,
			  "%s %s %s %s mtu %d netmask %s up",
			  IFCONFIG_PATH,
			  actual,
			  ifconfig_local,
			  ifconfig_local,
			  tun_mtu,
			  ifconfig_remote_netmask
			  );
	}
      else
      /*
       * NetBSD has distinct tun and tap devices
       * so we don't need the "link0" extra parameter to specify we want to do 
       * tunneling at the ethernet level
       */
		argv_printf (&argv,
			  "%s %s %s netmask %s mtu %d broadcast %s",
			  IFCONFIG_PATH,
			  actual,
			  ifconfig_local,
			  ifconfig_remote_netmask,
			  tun_mtu,
			  ifconfig_broadcast
			  );
      argv_msg (M_INFO, &argv);
      openvpn_execve_check (&argv, es, S_FATAL, "NetBSD ifconfig failed");

      if ( do_ipv6 )
	{
#ifdef NETBSD_MULTI_AF
	  argv_printf (&argv,
			  "%s %s inet6 %s/%d",
			  IFCONFIG_PATH,
			  actual,
			  ifconfig_ipv6_local,
			  tt->netbits_ipv6
			  );
	  argv_msg (M_INFO, &argv);
	  openvpn_execve_check (&argv, es, S_FATAL, "NetBSD ifconfig inet6 failed");

	  /* and, hooray, we explicitely need to add a route... */
	  add_route_connected_v6_net(tt, es);
#else
	  msg( M_INFO, "no IPv6 support for tun interfaces on NetBSD before 4.0 (if your system is newer, recompile openvpn)" );
	  tt->ipv6 = false;
#endif
	}
      tt->did_ifconfig = true;

#elif defined(TARGET_DARWIN)
      /*
       * Darwin (i.e. Mac OS X) seems to exhibit similar behaviour to OpenBSD...
       */

      argv_printf (&argv,
			"%s %s delete",
			IFCONFIG_PATH,
			actual);
      argv_msg (M_INFO, &argv);
      openvpn_execve_check (&argv, es, 0, NULL);
      msg (M_INFO, "NOTE: Tried to delete pre-existing tun/tap instance -- No Problem if failure");


      /* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
      if (tun)
	argv_printf (&argv,
			  "%s %s %s %s mtu %d netmask 255.255.255.255 up",
			  IFCONFIG_PATH,
			  actual,
			  ifconfig_local,
			  ifconfig_remote_netmask,
			  tun_mtu
			  );
      else
        {
          if (tt->topology == TOP_SUBNET)
    	    argv_printf (&argv,
			      "%s %s %s %s netmask %s mtu %d up",
			      IFCONFIG_PATH,
			      actual,
			      ifconfig_local,
			      ifconfig_local,
			      ifconfig_remote_netmask,
			      tun_mtu
			      );
	  else
    	    argv_printf (&argv,
			      "%s %s %s netmask %s mtu %d up",
			      IFCONFIG_PATH,
			      actual,
			      ifconfig_local,
			      ifconfig_remote_netmask,
			      tun_mtu
			      );
	}

      argv_msg (M_INFO, &argv);
      openvpn_execve_check (&argv, es, S_FATAL, "Mac OS X ifconfig failed");
      tt->did_ifconfig = true;

      /* Add a network route for the local tun interface */
      if (!tun && tt->topology == TOP_SUBNET)
	{
	  struct route_ipv4 r;
	  CLEAR (r);
	  r.flags = RT_DEFINED;
	  r.network = tt->local & tt->remote_netmask;
	  r.netmask = tt->remote_netmask;
	  r.gateway = tt->local;
	  add_route (&r, tt, 0, NULL, es);
	}

      if ( do_ipv6 )
	{
          argv_printf (&argv,
                              "%s %s inet6 %s/%d",
                              IFCONFIG_PATH,
                              actual,
                              ifconfig_ipv6_local,
                              tt->netbits_ipv6
                              );
	  argv_msg (M_INFO, &argv);
	  openvpn_execve_check (&argv, es, S_FATAL, "MacOS X ifconfig inet6 failed");

	  /* and, hooray, we explicitely need to add a route... */
	  add_route_connected_v6_net(tt, es);
	}

#elif defined(TARGET_FREEBSD)||defined(TARGET_DRAGONFLY)

      /* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
      if (tun)
	argv_printf (&argv,
			  "%s %s %s %s mtu %d netmask 255.255.255.255 up",
			  IFCONFIG_PATH,
			  actual,
			  ifconfig_local,
			  ifconfig_remote_netmask,
			  tun_mtu
			  );
      else if ( tt->topology == TOP_SUBNET )
	{
	    argv_printf (&argv,
			  "%s %s %s %s mtu %d netmask %s up",
			  IFCONFIG_PATH,
			  actual,
			  ifconfig_local,
			  create_arbitrary_remote( tt, &gc ),
			  tun_mtu,
			  ifconfig_remote_netmask
			  );
	}
      else
	argv_printf (&argv,
		      "%s %s %s netmask %s mtu %d up",
                              IFCONFIG_PATH,
                              actual,
                              ifconfig_local,
                              ifconfig_remote_netmask,
                              tun_mtu
                              );

      argv_msg (M_INFO, &argv);
      openvpn_execve_check (&argv, es, S_FATAL, "FreeBSD ifconfig failed");
      tt->did_ifconfig = true;

	/* Add a network route for the local tun interface */
      if (!tun && tt->topology == TOP_SUBNET)
        {
          struct route_ipv4 r;
          CLEAR (r);
          r.flags = RT_DEFINED;
          r.network = tt->local & tt->remote_netmask;
          r.netmask = tt->remote_netmask;
          r.gateway = tt->local;
          add_route (&r, tt, 0, NULL, es);
        }

      if ( do_ipv6 )
	{
          argv_printf (&argv,
                              "%s %s inet6 %s/%d",
                              IFCONFIG_PATH,
                              actual,
                              ifconfig_ipv6_local,
                              tt->netbits_ipv6
                              );
	  argv_msg (M_INFO, &argv);
	  openvpn_execve_check (&argv, es, S_FATAL, "FreeBSD ifconfig inet6 failed");
	}

#elif defined (WIN32)
      {
	/*
	 * Make sure that both ifconfig addresses are part of the
	 * same .252 subnet.
	 */
	if (tun)
	  {
	    verify_255_255_255_252 (tt->local, tt->remote_netmask);
	    tt->adapter_netmask = ~3;
	  }
	else
	  {
	    tt->adapter_netmask = tt->remote_netmask;
	  }

	switch (tt->options.ip_win32_type)
	  {
	  case IPW32_SET_MANUAL:
	    msg (M_INFO, "******** NOTE:  Please manually set the IP/netmask of '%s' to %s/%s (if it is not already set)",
		 actual,
		 ifconfig_local,
		 print_in_addr_t (tt->adapter_netmask, 0, &gc));
	    break;
	  case IPW32_SET_NETSH:
	    if (!strcmp (actual, "NULL"))
	      msg (M_FATAL, "Error: When using --ip-win32 netsh, if you have more than one TAP-Windows adapter, you must also specify --dev-node");

	    netsh_ifconfig (&tt->options,
			    actual,
			    tt->local,
			    tt->adapter_netmask,
			    NI_IP_NETMASK|NI_OPTIONS);

	    break;
	  }
	tt->did_ifconfig = true;
      }

    /* IPv6 always uses "netsh" interface */
    if ( do_ipv6 )
      {
	char * saved_actual;

	if (!strcmp (actual, "NULL"))
	  msg (M_FATAL, "Error: When using --tun-ipv6, if you have more than one TAP-Windows adapter, you must also specify --dev-node");

	/* example: netsh interface ipv6 set address MyTap 2001:608:8003::d store=active */
	argv_printf (&argv,
		    "%s%sc interface ipv6 set address %s %s store=active",
		     get_win_sys_path(),
		     NETSH_PATH_SUFFIX,
		     actual,
		     ifconfig_ipv6_local );

	netsh_command (&argv, 4);

	/* explicit route needed */
	/* on windows, OpenVPN does ifconfig first, open_tun later, so
	 * tt->actual_name might not yet be initialized, but routing code
	 * needs to know interface name - point to "actual", restore later
	 */
	saved_actual = tt->actual_name;
	tt->actual_name = (char*) actual;
	add_route_connected_v6_net(tt, es);
	tt->actual_name = saved_actual;
      }
#else
      msg (M_FATAL, "Sorry, but I don't know how to do 'ifconfig' commands on this operating system.  You should ifconfig your TUN/TAP device manually or use an --up script.");
#endif
      argv_reset (&argv);
    }
  gc_free (&gc);
}

static void
clear_tuntap (struct tuntap *tuntap)
{
  CLEAR (*tuntap);
#ifdef WIN32
  tuntap->hand = NULL;
#else
  tuntap->fd = -1;
#endif
#ifdef TARGET_SOLARIS
  tuntap->ip_fd = -1;
#endif
  tuntap->ipv6 = false;
}

static void
open_null (struct tuntap *tt)
{
  tt->actual_name = string_alloc ("null", NULL);
}


#if defined (TARGET_OPENBSD) || (defined(TARGET_DARWIN) && HAVE_NET_IF_UTUN_H)

/*
 * OpenBSD and Mac OS X when using utun
 * have a slightly incompatible TUN device from
 * the rest of the world, in that it prepends a
 * uint32 to the beginning of the IP header
 * to designate the protocol (why not just
 * look at the version field in the IP header to
 * determine v4 or v6?).
 *
 * We strip off this field on reads and
 * put it back on writes.
 *
 * I have not tested TAP devices on OpenBSD,
 * but I have conditionalized the special
 * TUN handling code described above to
 * go away for TAP devices.
 */

#include <netinet/ip.h>
#include <sys/uio.h>

static inline int
header_modify_read_write_return (int len)
{
    if (len > 0)
        return len > sizeof (u_int32_t) ? len - sizeof (u_int32_t) : 0;
    else
        return len;
}

int
write_tun_header (struct tuntap* tt, uint8_t *buf, int len)
{
    if (tt->type == DEV_TYPE_TUN)
      {
        u_int32_t type;
        struct iovec iv[2];
        struct ip *iph;

        iph = (struct ip *) buf;

        if (tt->ipv6 && iph->ip_v == 6)
            type = htonl (AF_INET6);
        else
            type = htonl (AF_INET);

        iv[0].iov_base = &type;
        iv[0].iov_len = sizeof (type);
        iv[1].iov_base = buf;
        iv[1].iov_len = len;

        return header_modify_read_write_return (writev (tt->fd, iv, 2));
      }
    else
        return write (tt->fd, buf, len);
}

int
read_tun_header (struct tuntap* tt, uint8_t *buf, int len)
{
    if (tt->type == DEV_TYPE_TUN)
      {
        u_int32_t type;
        struct iovec iv[2];

        iv[0].iov_base = &type;
        iv[0].iov_len = sizeof (type);
        iv[1].iov_base = buf;
        iv[1].iov_len = len;

        return header_modify_read_write_return (readv (tt->fd, iv, 2));
      }
    else
        return read (tt->fd, buf, len);
}
#endif


#ifndef WIN32
static void
open_tun_generic (const char *dev, const char *dev_type, const char *dev_node,
		  bool ipv6_explicitly_supported, bool dynamic,
		  struct tuntap *tt)
{
  char tunname[256];
  char dynamic_name[256];
  bool dynamic_opened = false;


  if ( tt->ipv6 && ! ipv6_explicitly_supported )
    msg (M_WARN, "NOTE: explicit support for IPv6 tun devices is not provided for this OS");

  if (tt->type == DEV_TYPE_NULL)
    {
      open_null (tt);
    }
  else
    {
      /*
       * --dev-node specified, so open an explicit device node
       */
      if (dev_node)
	{
	  openvpn_snprintf (tunname, sizeof (tunname), "%s", dev_node);
	}
      else
	{
	  /*
	   * dynamic open is indicated by --dev specified without
	   * explicit unit number.  Try opening /dev/[dev]n
	   * where n = [0, 255].
	   */
#ifdef TARGET_NETBSD
	  /* on NetBSD, tap (but not tun) devices are opened by
           * opening /dev/tap and then querying the system about the
	   * actual device name (tap0, tap1, ...) assigned
           */
	  if ( dynamic && strcmp( dev, "tap" ) == 0 )
	    {
	      struct ifreq ifr;
	      if ((tt->fd = open ( "/dev/tap", O_RDWR)) < 0)
		{
		  msg (M_FATAL, "Cannot allocate NetBSD TAP dev dynamically");
		}
	      if ( ioctl( tt->fd, TAPGIFNAME, (void*)&ifr ) < 0 )
		{
		  msg (M_FATAL, "Cannot query NetBSD TAP device name");
		}
	      CLEAR(dynamic_name);
	      strncpy( dynamic_name, ifr.ifr_name, sizeof(dynamic_name)-1 );
	      dynamic_opened = true;
	      openvpn_snprintf (tunname, sizeof (tunname), "/dev/%s", dynamic_name );
	    }
	  else
#endif

	  if (dynamic && !has_digit((unsigned char *)dev))
	    {
	      int i;
	      for (i = 0; i < 256; ++i)
		{
		  openvpn_snprintf (tunname, sizeof (tunname),
				    "/dev/%s%d", dev, i);
		  openvpn_snprintf (dynamic_name, sizeof (dynamic_name),
				    "%s%d", dev, i);
		  if ((tt->fd = open (tunname, O_RDWR)) > 0)
		    {
		      dynamic_opened = true;
		      break;
		    }
		  msg (D_READ_WRITE | M_ERRNO, "Tried opening %s (failed)", tunname);
		}
	      if (!dynamic_opened)
		msg (M_FATAL, "Cannot allocate TUN/TAP dev dynamically");
	    }
	  /*
	   * explicit unit number specified
	   */
	  else
	    {
	      openvpn_snprintf (tunname, sizeof (tunname), "/dev/%s", dev);
	    }
	}

      if (!dynamic_opened)
	{
	  /* has named device existed before? if so, don't destroy at end */
	  if ( if_nametoindex( dev ) > 0 )
	    {
	      msg (M_INFO, "TUN/TAP device %s exists previously, keep at program end", dev );
	      tt->persistent_if = true;
	    }

	  if ((tt->fd = open (tunname, O_RDWR)) < 0)
	    msg (M_ERR, "Cannot open TUN/TAP dev %s", tunname);
	}

      set_nonblock (tt->fd);
      set_cloexec (tt->fd); /* don't pass fd to scripts */
      msg (M_INFO, "TUN/TAP device %s opened", tunname);

      /* tt->actual_name is passed to up and down scripts and used as the ifconfig dev name */
      tt->actual_name = string_alloc (dynamic_opened ? dynamic_name : dev, NULL);
    }
}

static void
close_tun_generic (struct tuntap *tt)
{
  if (tt->fd >= 0)
    close (tt->fd);
  if (tt->actual_name)
    free (tt->actual_name);
  clear_tuntap (tt);
}

#endif

#if defined(TARGET_LINUX)

#ifdef HAVE_LINUX_IF_TUN_H	/* New driver support */

#ifndef HAVE_LINUX_SOCKIOS_H
#error header file linux/sockios.h required
#endif

#if !PEDANTIC

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
  struct ifreq ifr;

  /*
   * We handle --dev null specially, we do not open /dev/null for this.
   */
  if (tt->type == DEV_TYPE_NULL)
    {
      open_null (tt);
    }
  else
    {
      /*
       * Process --dev-node
       */
      const char *node = dev_node;
      if (!node)
	node = "/dev/net/tun";

      /*
       * Open the interface
       */
      if ((tt->fd = open (node, O_RDWR)) < 0)
	{
	  msg (M_ERR, "ERROR: Cannot open TUN/TAP dev %s", node);
	}

      /*
       * Process --tun-ipv6
       */
      CLEAR (ifr);
      if (!tt->ipv6)
	ifr.ifr_flags = IFF_NO_PI;

#if defined(IFF_ONE_QUEUE) && defined(SIOCSIFTXQLEN)
      ifr.ifr_flags |= IFF_ONE_QUEUE;
#endif

      /*
       * Figure out if tun or tap device
       */
      if (tt->type == DEV_TYPE_TUN)
	{
	  ifr.ifr_flags |= IFF_TUN;
	}
      else if (tt->type == DEV_TYPE_TAP)
	{
	  ifr.ifr_flags |= IFF_TAP;
	}
      else
	{
	  msg (M_FATAL, "I don't recognize device %s as a tun or tap device",
	       dev);
	}

      /*
       * Set an explicit name, if --dev is not tun or tap
       */
      if (strcmp(dev, "tun") && strcmp(dev, "tap"))
	strncpynt (ifr.ifr_name, dev, IFNAMSIZ);

      /*
       * Use special ioctl that configures tun/tap device with the parms
       * we set in ifr
       */
      if (ioctl (tt->fd, TUNSETIFF, (void *) &ifr) < 0)
	{
	  msg (M_ERR, "ERROR: Cannot ioctl TUNSETIFF %s", dev);
	}

      msg (M_INFO, "TUN/TAP device %s opened", ifr.ifr_name);

      /*
       * Try making the TX send queue bigger
       */
#if defined(IFF_ONE_QUEUE) && defined(SIOCSIFTXQLEN)
      if (tt->options.txqueuelen) {
	struct ifreq netifr;
	int ctl_fd;

	if ((ctl_fd = socket (AF_INET, SOCK_DGRAM, 0)) >= 0)
	  {
	    CLEAR (netifr);
	    strncpynt (netifr.ifr_name, ifr.ifr_name, IFNAMSIZ);
	    netifr.ifr_qlen = tt->options.txqueuelen;
	    if (ioctl (ctl_fd, SIOCSIFTXQLEN, (void *) &netifr) >= 0)
	      msg (D_OSBUF, "TUN/TAP TX queue length set to %d", tt->options.txqueuelen);
	    else
	      msg (M_WARN | M_ERRNO, "Note: Cannot set tx queue length on %s", ifr.ifr_name);
	    close (ctl_fd);
	  }
	else
	  {
	    msg (M_WARN | M_ERRNO, "Note: Cannot open control socket on %s", ifr.ifr_name);
	  }
      }
#endif

      set_nonblock (tt->fd);
      set_cloexec (tt->fd);
      tt->actual_name = string_alloc (ifr.ifr_name, NULL);
    }
  return;
}

#else

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
  ASSERT (0);
}

#endif

#else

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
  open_tun_generic (dev, dev_type, dev_node, false, true, tt);
}

#endif /* HAVE_LINUX_IF_TUN_H */

#ifdef ENABLE_FEATURE_TUN_PERSIST

/*
 * This can be removed in future
 * when all systems will use newer
 * linux-headers
 */
#ifndef TUNSETOWNER
#define TUNSETOWNER	_IOW('T', 204, int)
#endif
#ifndef TUNSETGROUP
#define TUNSETGROUP	_IOW('T', 206, int)
#endif

void
tuncfg (const char *dev, const char *dev_type, const char *dev_node, int persist_mode, const char *username, const char *groupname, const struct tuntap_options *options)
{
  struct tuntap *tt;

  ALLOC_OBJ (tt, struct tuntap);
  clear_tuntap (tt);
  tt->type = dev_type_enum (dev, dev_type);
  tt->options = *options;
  open_tun (dev, dev_type, dev_node, tt);
  if (ioctl (tt->fd, TUNSETPERSIST, persist_mode) < 0)
    msg (M_ERR, "Cannot ioctl TUNSETPERSIST(%d) %s", persist_mode, dev);
  if (username != NULL)
    {
      struct platform_state_user platform_state_user;

      if (!platform_user_get (username, &platform_state_user))
        msg (M_ERR, "Cannot get user entry for %s", username);
      else
        if (ioctl (tt->fd, TUNSETOWNER, platform_state_user.pw->pw_uid) < 0)
          msg (M_ERR, "Cannot ioctl TUNSETOWNER(%s) %s", username, dev);
    }
  if (groupname != NULL)
    {
      struct platform_state_group platform_state_group;

      if (!platform_group_get (groupname, &platform_state_group))
        msg (M_ERR, "Cannot get group entry for %s", groupname);
      else
        if (ioctl (tt->fd, TUNSETGROUP, platform_state_group.gr->gr_gid) < 0)
          msg (M_ERR, "Cannot ioctl TUNSETOWNER(%s) %s", groupname, dev);
    }
  close_tun (tt);
  msg (M_INFO, "Persist state set to: %s", (persist_mode ? "ON" : "OFF"));
}

#endif /* ENABLE_FEATURE_TUN_PERSIST */

void
close_tun (struct tuntap *tt)
{
  if (tt)
    {
	if (tt->type != DEV_TYPE_NULL && tt->did_ifconfig)
	  {
	    struct argv argv;
	    struct gc_arena gc = gc_new ();
	    argv_init (&argv);

#ifdef ENABLE_IPROUTE
	    if (is_tun_p2p (tt))
	      {
		argv_printf (&argv,
			"%s addr del dev %s local %s peer %s",
			iproute_path,
			tt->actual_name,
			print_in_addr_t (tt->local, 0, &gc),
			print_in_addr_t (tt->remote_netmask, 0, &gc)
			);
	      }
	    else
	      {
		argv_printf (&argv,
			"%s addr del dev %s %s/%d",
			iproute_path,
			tt->actual_name,
			print_in_addr_t (tt->local, 0, &gc),
			count_netmask_bits(print_in_addr_t (tt->remote_netmask, 0, &gc))
			);
	      }
#else
	    argv_printf (&argv,
			"%s %s 0.0.0.0",
			IFCONFIG_PATH,
			tt->actual_name
			);
#endif

	    argv_msg (M_INFO, &argv);
	    openvpn_execve_check (&argv, NULL, 0, "Linux ip addr del failed");

            if (tt->ipv6 && tt->did_ifconfig_ipv6_setup)
              {
                const char * ifconfig_ipv6_local = print_in6_addr (tt->local_ipv6, 0, &gc);

#ifdef ENABLE_IPROUTE
                argv_printf (&argv, "%s -6 addr del %s/%d dev %s",
                                    iproute_path,
                                    ifconfig_ipv6_local,
                                    tt->netbits_ipv6,
                                    tt->actual_name
                                    );
                argv_msg (M_INFO, &argv);
                openvpn_execve_check (&argv, NULL, 0, "Linux ip -6 addr del failed");
#else
                argv_printf (&argv,
                            "%s %s del %s/%d",
                            IFCONFIG_PATH,
                            tt->actual_name,
                            ifconfig_ipv6_local,
                            tt->netbits_ipv6
                            );
                argv_msg (M_INFO, &argv);
                openvpn_execve_check (&argv, NULL, 0, "Linux ifconfig inet6 del failed");
#endif
              }

	    argv_reset (&argv);
	    gc_free (&gc);
	  }
      close_tun_generic (tt);
      free (tt);
    }
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  if (tt->ipv6)
    {
      struct tun_pi pi;
      struct iphdr *iph;
      struct iovec vect[2];
      int ret;

      iph = (struct iphdr *)buf;

      pi.flags = 0;

      if(iph->version == 6)
	pi.proto = htons(OPENVPN_ETH_P_IPV6);
      else
	pi.proto = htons(OPENVPN_ETH_P_IPV4);

      vect[0].iov_len = sizeof(pi);
      vect[0].iov_base = &pi;
      vect[1].iov_len = len;
      vect[1].iov_base = buf;

      ret = writev(tt->fd, vect, 2);
      return(ret - sizeof(pi));
    }
  else
    return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  if (tt->ipv6)
    {
      struct iovec vect[2];
      struct tun_pi pi;
      int ret;

      vect[0].iov_len = sizeof(pi);
      vect[0].iov_base = &pi;
      vect[1].iov_len = len;
      vect[1].iov_base = buf;

      ret = readv(tt->fd, vect, 2);
      return(ret - sizeof(pi));
    }
  else
    return read (tt->fd, buf, len);
}

#elif defined(TARGET_SOLARIS)

#ifndef TUNNEWPPA
#error I need the symbol TUNNEWPPA from net/if_tun.h
#endif

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
  int if_fd, ip_muxid, arp_muxid, arp_fd, ppa = -1;
  struct lifreq ifr;
  const char *ptr;
  const char *ip_node, *arp_node;
  const char *dev_tuntap_type;
  int link_type;
  bool is_tun;
  struct strioctl  strioc_if, strioc_ppa;

  /* improved generic TUN/TAP driver from
   * http://www.whiteboard.ne.jp/~admin2/tuntap/
   * has IPv6 support
   */
  CLEAR(ifr);

  if (tt->type == DEV_TYPE_NULL)
    {
      open_null (tt);
      return;
    }

  if (tt->type == DEV_TYPE_TUN)
    {
      ip_node = "/dev/udp";
      if (!dev_node)
	dev_node = "/dev/tun";
      dev_tuntap_type = "tun";
      link_type = I_PLINK;
      is_tun = true;
    }
  else if (tt->type == DEV_TYPE_TAP)
    {
      ip_node = "/dev/udp";
      if (!dev_node)
	dev_node = "/dev/tap";
      arp_node = dev_node;
      dev_tuntap_type = "tap";
      link_type = I_PLINK; /* was: I_LINK */
      is_tun = false;
    }
  else
    {
      msg (M_FATAL, "I don't recognize device %s as a tun or tap device",
	   dev);
    }

  if ((tt->ip_fd = open (ip_node, O_RDWR, 0)) < 0)
    msg (M_ERR, "Can't open %s", ip_node);

  if ((tt->fd = open (dev_node, O_RDWR, 0)) < 0)
    msg (M_ERR, "Can't open %s", dev_node);
  
  /* get unit number */
  if (*dev)
    {
      ptr = dev;
      while (*ptr && !isdigit ((int) *ptr))
	ptr++;
      ppa = atoi (ptr);
    }

  /* Assign a new PPA and get its unit number. */
  strioc_ppa.ic_cmd = TUNNEWPPA;
  strioc_ppa.ic_timout = 0;
  strioc_ppa.ic_len = sizeof(ppa);
  strioc_ppa.ic_dp = (char *)&ppa;

  if ( *ptr == '\0' )		/* no number given, try dynamic */
    {
      bool found_one = false;
      while( ! found_one && ppa < 64 )
	{
	  int new_ppa = ioctl (tt->fd, I_STR, &strioc_ppa);
	  if ( new_ppa >= 0 )
	    {
	      msg( M_INFO, "open_tun: got dynamic interface '%s%d'", dev_tuntap_type, new_ppa );
	      ppa = new_ppa;
	      found_one = true;
	      break;
	    }
	  if ( errno != EEXIST )
	    msg (M_ERR, "open_tun: unexpected error trying to find free %s interface", dev_tuntap_type );
	  ppa++;
	}
      if ( !found_one )
	msg (M_ERR, "open_tun: could not find free %s interface, give up.", dev_tuntap_type );
    }
  else				/* try this particular one */
    {
      if ((ppa = ioctl (tt->fd, I_STR, &strioc_ppa)) < 0)
        msg (M_ERR, "Can't assign PPA for new interface (%s%d)", dev_tuntap_type, ppa );
    }

  if ((if_fd = open (dev_node, O_RDWR, 0)) < 0)
    msg (M_ERR, "Can't open %s (2)", dev_node);

  if (ioctl (if_fd, I_PUSH, "ip") < 0)
    msg (M_ERR, "Can't push IP module");

  if (tt->type == DEV_TYPE_TUN)
    {
  /* Assign ppa according to the unit number returned by tun device */
  if (ioctl (if_fd, IF_UNITSEL, (char *) &ppa) < 0)
    msg (M_ERR, "Can't set PPA %d", ppa);
    }

  tt->actual_name = (char *) malloc (32);
  check_malloc_return (tt->actual_name);

  openvpn_snprintf (tt->actual_name, 32, "%s%d", dev_tuntap_type, ppa);

  if (tt->type == DEV_TYPE_TAP)
    {
          if (ioctl(if_fd, SIOCGLIFFLAGS, &ifr) < 0)
            msg (M_ERR, "Can't get flags\n");
          strncpynt (ifr.lifr_name, tt->actual_name, sizeof (ifr.lifr_name));
          ifr.lifr_ppa = ppa;
          /* Assign ppa according to the unit number returned by tun device */
          if (ioctl (if_fd, SIOCSLIFNAME, &ifr) < 0)
            msg (M_ERR, "Can't set PPA %d", ppa);
          if (ioctl(if_fd, SIOCGLIFFLAGS, &ifr) <0)
            msg (M_ERR, "Can't get flags\n");
          /* Push arp module to if_fd */
          if (ioctl (if_fd, I_PUSH, "arp") < 0)
            msg (M_ERR, "Can't push ARP module");

          /* Pop any modules on the stream */
          while (true)
            {
                 if (ioctl (tt->ip_fd, I_POP, NULL) < 0)
                     break;
            }
          /* Push arp module to ip_fd */
          if (ioctl (tt->ip_fd, I_PUSH, "arp") < 0)
            msg (M_ERR, "Can't push ARP module\n");

          /* Open arp_fd */
          if ((arp_fd = open (arp_node, O_RDWR, 0)) < 0)
            msg (M_ERR, "Can't open %s\n", arp_node);
          /* Push arp module to arp_fd */
          if (ioctl (arp_fd, I_PUSH, "arp") < 0)
            msg (M_ERR, "Can't push ARP module\n");

          /* Set ifname to arp */
          strioc_if.ic_cmd = SIOCSLIFNAME;
          strioc_if.ic_timout = 0;
          strioc_if.ic_len = sizeof(ifr);
          strioc_if.ic_dp = (char *)&ifr;
          if (ioctl(arp_fd, I_STR, &strioc_if) < 0){
              msg (M_ERR, "Can't set ifname to arp\n");
          }
   }

  if ((ip_muxid = ioctl (tt->ip_fd, link_type, if_fd)) < 0)
    msg (M_ERR, "Can't link %s device to IP", dev_tuntap_type);

  if (tt->type == DEV_TYPE_TAP) {
          if ((arp_muxid = ioctl (tt->ip_fd, link_type, arp_fd)) < 0)
            msg (M_ERR, "Can't link %s device to ARP", dev_tuntap_type);
          close (arp_fd);
  }

  CLEAR (ifr);
  strncpynt (ifr.lifr_name, tt->actual_name, sizeof (ifr.lifr_name));
  ifr.lifr_ip_muxid  = ip_muxid;
  if (tt->type == DEV_TYPE_TAP) {
          ifr.lifr_arp_muxid = arp_muxid;
  }

  if (ioctl (tt->ip_fd, SIOCSLIFMUXID, &ifr) < 0)
    {
      if (tt->type == DEV_TYPE_TAP)
        {
              ioctl (tt->ip_fd, I_PUNLINK , arp_muxid);
        }
      ioctl (tt->ip_fd, I_PUNLINK, ip_muxid);
      msg (M_ERR, "Can't set multiplexor id");
    }

  set_nonblock (tt->fd);
  set_cloexec (tt->fd);
  set_cloexec (tt->ip_fd);

  msg (M_INFO, "TUN/TAP device %s opened", tt->actual_name);
}

static void
solaris_close_tun (struct tuntap *tt)
{
  if (tt)
    {
      /* IPv6 interfaces need to be 'manually' de-configured */
      if ( tt->ipv6 && tt->did_ifconfig_ipv6_setup )
	{
	  struct argv argv;
	  argv_init (&argv);
	  argv_printf( &argv, "%s %s inet6 unplumb",
		       IFCONFIG_PATH, tt->actual_name );
	  argv_msg (M_INFO, &argv);
	  openvpn_execve_check (&argv, NULL, 0, "Solaris ifconfig inet6 unplumb failed");
	  argv_reset (&argv);
	}

      if (tt->ip_fd >= 0)
	{
          struct lifreq ifr;
	  CLEAR (ifr);
          strncpynt (ifr.lifr_name, tt->actual_name, sizeof (ifr.lifr_name));

          if (ioctl (tt->ip_fd, SIOCGLIFFLAGS, &ifr) < 0)
	    msg (M_WARN | M_ERRNO, "Can't get iface flags");

          if (ioctl (tt->ip_fd, SIOCGLIFMUXID, &ifr) < 0)
	    msg (M_WARN | M_ERRNO, "Can't get multiplexor id");

          if (tt->type == DEV_TYPE_TAP)
            {
                  if (ioctl (tt->ip_fd, I_PUNLINK, ifr.lifr_arp_muxid) < 0)
                    msg (M_WARN | M_ERRNO, "Can't unlink interface(arp)");
            }

          if (ioctl (tt->ip_fd, I_PUNLINK, ifr.lifr_ip_muxid) < 0)
            msg (M_WARN | M_ERRNO, "Can't unlink interface(ip)");

	  close (tt->ip_fd);
	  tt->ip_fd = -1;
	}

      if (tt->fd >= 0)
	{
	  close (tt->fd);
	  tt->fd = -1;
	}
    }
}

/*
 * Close TUN device. 
 */
void
close_tun (struct tuntap *tt)
{
  if (tt)
    {
      solaris_close_tun (tt);

      if (tt->actual_name)
	free (tt->actual_name);
      
      clear_tuntap (tt);
      free (tt);
    }
}

static void
solaris_error_close (struct tuntap *tt, const struct env_set *es, 
                     const char *actual, bool unplumb_inet6 )
{
  struct argv argv;
  argv_init (&argv);

  if (unplumb_inet6)
    {
      argv_printf( &argv, "%s %s inet6 unplumb",
		   IFCONFIG_PATH, actual );
      argv_msg (M_INFO, &argv);
      openvpn_execve_check (&argv, es, 0, "Solaris ifconfig inet6 unplumb failed");
    }

  argv_printf (&argv,
		    "%s %s unplumb",
		    IFCONFIG_PATH,
		    actual);

  argv_msg (M_INFO, &argv);
  openvpn_execve_check (&argv, es, 0, "Solaris ifconfig unplumb failed");
  close_tun (tt);
  msg (M_FATAL, "Solaris ifconfig failed");
  argv_reset (&argv);
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  struct strbuf sbuf;
  sbuf.len = len;
  sbuf.buf = (char *)buf;
  return putmsg (tt->fd, NULL, &sbuf, 0) >= 0 ? sbuf.len : -1;
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  struct strbuf sbuf;
  int f = 0;

  sbuf.maxlen = len;
  sbuf.buf = (char *)buf;
  return getmsg (tt->fd, NULL, &sbuf, &f) >= 0 ? sbuf.len : -1;
}

#elif defined(TARGET_OPENBSD)

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
  open_tun_generic (dev, dev_type, dev_node, true, true, tt);

  /* Enable multicast on the interface */
  if (tt->fd >= 0)
    {
      struct tuninfo info;

      if (ioctl (tt->fd, TUNGIFINFO, &info) < 0) {
	msg (M_WARN | M_ERRNO, "Can't get interface info: %s",
	  strerror(errno));
      }

#ifdef IFF_MULTICAST /* openbsd 4.x doesn't have this */
      info.flags |= IFF_MULTICAST;
#endif

      if (ioctl (tt->fd, TUNSIFINFO, &info) < 0) {
	msg (M_WARN | M_ERRNO, "Can't set interface info: %s",
	  strerror(errno));
      }
    }
}

/* tun(4): "If the device was created by opening /dev/tunN, it will be
 *          automatically destroyed.  Devices created via ifconfig(8) are
 *          only marked as not running and traffic will be dropped
 *          returning EHOSTDOWN."
 * --> no special handling should be needed - *but* OpenBSD is misbehaving
 * here: if the interface was put in tap mode ("ifconfig tunN link0"), it
 * *will* stay around, and needs to be cleaned up manually
 */

void
close_tun (struct tuntap* tt)
{
  /* only *TAP* devices need destroying, tun devices auto-self-destruct
   */
  if (tt && (tt->type == DEV_TYPE_TUN || tt->persistent_if ) )
    {
      close_tun_generic (tt);
      free(tt);
    }
  else if (tt)
    {
      struct gc_arena gc = gc_new ();
      struct argv argv;

      /* setup command, close tun dev (clears tt->actual_name!), run command
       */

      argv_init (&argv);
      argv_printf (&argv, "%s %s destroy",
                          IFCONFIG_PATH, tt->actual_name);

      close_tun_generic (tt);

      argv_msg (M_INFO, &argv);
      openvpn_execve_check (&argv, NULL, 0, "OpenBSD 'destroy tun interface' failed (non-critical)");

      free (tt);
    }
}

int
write_tun(struct tuntap *tt, uint8_t *buf, int len)
{
  return write_tun_header (tt, buf, len);
}

int
read_tun (struct tuntap *tt, uint8_t *buf, int len)
{
    return read_tun_header (tt, buf, len);
}

#elif defined(TARGET_NETBSD)

/*
 * NetBSD before 4.0 does not support IPv6 on tun out of the box,
 * but there exists a patch (sys/net/if_tun.c, 1.79->1.80, see PR 32944).
 *
 * NetBSD 4.0 and up do, but we need to put the tun interface into
 * "multi_af" mode, which will prepend the address family to all packets
 * (same as OpenBSD and FreeBSD).  If this is not enabled, the kernel
 * silently drops all IPv6 packets on output and gets confused on input.
 *
 * On earlier versions, multi_af is not available at all, so we have
 * two different NetBSD code variants here :-(
 *
 */

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
#ifdef NETBSD_MULTI_AF
    open_tun_generic (dev, dev_type, dev_node, true, true, tt);
#else
    open_tun_generic (dev, dev_type, dev_node, false, true, tt);
#endif

    if (tt->fd >= 0)
      {
        int i = IFF_POINTOPOINT|IFF_MULTICAST;
        ioctl (tt->fd, TUNSIFMODE, &i);  /* multicast on */
        i = 0;
        ioctl (tt->fd, TUNSLMODE, &i);   /* link layer mode off */

#ifdef NETBSD_MULTI_AF
	if ( tt->type == DEV_TYPE_TUN )
	  {
	    i = 1;
	    if (ioctl (tt->fd, TUNSIFHEAD, &i) < 0) 	/* multi-af mode on */
	      {
		msg (M_WARN | M_ERRNO, "ioctl(TUNSIFHEAD): %s", strerror(errno));
	      }
	  }
#endif
      }
}

/* the current way OpenVPN handles tun devices on NetBSD leads to
 * lingering tunX interfaces after close -> for a full cleanup, they
 * need to be explicitely destroyed
 */
void
close_tun (struct tuntap *tt)
{
  /* only tun devices need destroying, tap devices auto-self-destruct
   */
  if (tt && ( tt->type != DEV_TYPE_TUN || tt->persistent_if ) )
    {
      close_tun_generic (tt);
      free(tt);
    }
  else if (tt)
    {
      struct gc_arena gc = gc_new ();
      struct argv argv;

      /* setup command, close tun dev (clears tt->actual_name!), run command
       */

      argv_init (&argv);
      argv_printf (&argv, "%s %s destroy",
                          IFCONFIG_PATH, tt->actual_name);

      close_tun_generic (tt);

      argv_msg (M_INFO, &argv);
      openvpn_execve_check (&argv, NULL, 0, "NetBSD 'destroy tun interface' failed (non-critical)");

      free (tt);
    }
}

#ifdef NETBSD_MULTI_AF

static inline int
netbsd_modify_read_write_return (int len)
{
  if (len > 0)
    return len > sizeof (u_int32_t) ? len - sizeof (u_int32_t) : 0;
  else
    return len;
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  if (tt->type == DEV_TYPE_TUN)
    {
      u_int32_t type;
      struct iovec iv[2];
      struct openvpn_iphdr *iph;

      iph = (struct openvpn_iphdr *) buf;

      if (tt->ipv6 && OPENVPN_IPH_GET_VER(iph->version_len) == 6)
        type = htonl (AF_INET6);
      else 
        type = htonl (AF_INET);

      iv[0].iov_base = (char *)&type;
      iv[0].iov_len = sizeof (type);
      iv[1].iov_base = buf;
      iv[1].iov_len = len;

      return netbsd_modify_read_write_return (writev (tt->fd, iv, 2));
    }
  else
    return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  if (tt->type == DEV_TYPE_TUN)
    {
      u_int32_t type;
      struct iovec iv[2];

      iv[0].iov_base = (char *)&type;
      iv[0].iov_len = sizeof (type);
      iv[1].iov_base = buf;
      iv[1].iov_len = len;

      return netbsd_modify_read_write_return (readv (tt->fd, iv, 2));
    }
  else
    return read (tt->fd, buf, len);
}

#else	/* not NETBSD_MULTI_AF -> older code, IPv4 only */

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
    return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
    return read (tt->fd, buf, len);
}
#endif	/* NETBSD_MULTI_AF */

#elif defined(TARGET_FREEBSD)

static inline int
freebsd_modify_read_write_return (int len)
{
  if (len > 0)
    return len > sizeof (u_int32_t) ? len - sizeof (u_int32_t) : 0;
  else
    return len;
}

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
  open_tun_generic (dev, dev_type, dev_node, true, true, tt);

  if (tt->fd >= 0 && tt->type == DEV_TYPE_TUN)
    {
      int i = IFF_POINTOPOINT | IFF_MULTICAST;

      if (ioctl (tt->fd, TUNSIFMODE, &i) < 0) {
	msg (M_WARN | M_ERRNO, "ioctl(TUNSIFMODE): %s", strerror(errno));
      }
      i = 1;
      if (ioctl (tt->fd, TUNSIFHEAD, &i) < 0) {
	msg (M_WARN | M_ERRNO, "ioctl(TUNSIFHEAD): %s", strerror(errno));
      }
    }
}

/* tun(4): "These network interfaces persist until the if_tun.ko module is
 *          unloaded, or until removed with the ifconfig(8) command."
 *          (verified for FreeBSD 6.3, 7.4, 8.2 and 9, same for tap(4))
 *
 * so, to avoid lingering tun/tap interfaces after OpenVPN quits,
 * we need to call "ifconfig ... destroy" for cleanup
 */
void
close_tun (struct tuntap *tt)
{
  if (tt && tt->persistent_if )		/* keep pre-existing if around */
    {
      close_tun_generic (tt);
      free (tt);
    }
  else if (tt)				/* close and destroy */
    {
      struct gc_arena gc = gc_new ();
      struct argv argv;

      /* setup command, close tun dev (clears tt->actual_name!), run command
       */

      argv_init (&argv);
      argv_printf (&argv, "%s %s destroy",
                          IFCONFIG_PATH, tt->actual_name);

      close_tun_generic (tt);

      argv_msg (M_INFO, &argv);
      openvpn_execve_check (&argv, NULL, 0, "FreeBSD 'destroy tun interface' failed (non-critical)");

      free (tt);
    }
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  if (tt->type == DEV_TYPE_TUN)
    {
      u_int32_t type;
      struct iovec iv[2];
      struct ip *iph;

      iph = (struct ip *) buf;

      if (tt->ipv6 && iph->ip_v == 6)
        type = htonl (AF_INET6);
      else 
        type = htonl (AF_INET);

      iv[0].iov_base = (char *)&type;
      iv[0].iov_len = sizeof (type);
      iv[1].iov_base = buf;
      iv[1].iov_len = len;

      return freebsd_modify_read_write_return (writev (tt->fd, iv, 2));
    }
  else
    return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  if (tt->type == DEV_TYPE_TUN)
    {
      u_int32_t type;
      struct iovec iv[2];

      iv[0].iov_base = (char *)&type;
      iv[0].iov_len = sizeof (type);
      iv[1].iov_base = buf;
      iv[1].iov_len = len;

      return freebsd_modify_read_write_return (readv (tt->fd, iv, 2));
    }
  else
    return read (tt->fd, buf, len);
}

#elif defined(TARGET_DRAGONFLY)

static inline int
dragonfly_modify_read_write_return (int len)
{
  if (len > 0)
    return len > sizeof (u_int32_t) ? len - sizeof (u_int32_t) : 0;
  else
    return len;
}

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
  open_tun_generic (dev, dev_type, dev_node, true, true, tt);

  if (tt->fd >= 0)
    {
      int i = 0;

      /* Disable extended modes */
      ioctl (tt->fd, TUNSLMODE, &i);
      i = 1;
      ioctl (tt->fd, TUNSIFHEAD, &i);
    }
}

void
close_tun (struct tuntap *tt)
{
  if (tt)
    {
      close_tun_generic (tt);
      free (tt);
    }
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  if (tt->type == DEV_TYPE_TUN)
    {
      u_int32_t type;
      struct iovec iv[2];
      struct ip *iph;

      iph = (struct ip *) buf;

      if (tt->ipv6 && iph->ip_v == 6)
        type = htonl (AF_INET6);
      else 
        type = htonl (AF_INET);

      iv[0].iov_base = (char *)&type;
      iv[0].iov_len = sizeof (type);
      iv[1].iov_base = buf;
      iv[1].iov_len = len;

      return dragonfly_modify_read_write_return (writev (tt->fd, iv, 2));
    }
  else
    return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  if (tt->type == DEV_TYPE_TUN)
    {
      u_int32_t type;
      struct iovec iv[2];

      iv[0].iov_base = (char *)&type;
      iv[0].iov_len = sizeof (type);
      iv[1].iov_base = buf;
      iv[1].iov_len = len;

      return dragonfly_modify_read_write_return (readv (tt->fd, iv, 2));
    }
  else
    return read (tt->fd, buf, len);
}

#elif defined(TARGET_DARWIN)

/* Darwin (MacOS X) is mostly "just use the generic stuff", but there
 * is always one caveat...:
 *
 * If IPv6 is configured, and the tun device is closed, the IPv6 address
 * configured to the tun interface changes to a lingering /128 route
 * pointing to lo0.  Need to unconfigure...  (observed on 10.5)
 */

/*
 * utun is the native Darwin tun driver present since at least 10.7
 * Thanks goes to Jonathan Levin for providing an example how to utun
 * (http://newosxbook.com/src.jl?tree=listings&file=17-15-utun.c)
 */

#ifdef HAVE_NET_IF_UTUN_H

/* Helper functions that tries to open utun device
   return -2 on early initialization failures (utun not supported
   at all (old OS X) and -1 on initlization failure of utun
   device (utun works but utunX is already used */
static
int utun_open_helper (struct ctl_info ctlInfo, int utunnum)
{
  struct sockaddr_ctl sc;
  int fd;

  fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

  if (fd < 0)
    {
      msg (M_INFO, "Opening utun (%s): %s", "socket(SYSPROTO_CONTROL)",
           strerror (errno));
      return -2;
    }

  if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1)
    {
      close (fd);
      msg (M_INFO, "Opening utun (%s): %s", "ioctl(CTLIOCGINFO)",
           strerror (errno));
      return -2;
    }


  sc.sc_id = ctlInfo.ctl_id;
  sc.sc_len = sizeof(sc);
  sc.sc_family = AF_SYSTEM;
  sc.ss_sysaddr = AF_SYS_CONTROL;

  sc.sc_unit = utunnum+1;


  /* If the connect is successful, a utun%d device will be created, where "%d"
   * is (sc.sc_unit - 1) */

  if (connect (fd, (struct sockaddr *)&sc, sizeof(sc)) < 0)
    {
      msg (M_INFO, "Opening utun (%s): %s", "connect(AF_SYS_CONTROL)",
           strerror (errno));
      close(fd);
      return -1;
    }

  set_nonblock (fd);
  set_cloexec (fd); /* don't pass fd to scripts */

  return fd;
}

void
open_darwin_utun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
  struct ctl_info ctlInfo;
  int fd;
  char utunname[20];
  int utunnum =-1;
  socklen_t utunname_len = sizeof(utunname);

  /* dev_node is simply utun, do the normal dynamic utun
   * otherwise try to parse the utun number */
  if (dev_node && !strcmp ("utun", dev_node)==0)
    {
      if (!sscanf (dev_node, "utun%d", &utunnum)==1)
        msg (M_FATAL, "Cannot parse 'dev-node %s' please use 'dev-node utunX'"
             "to use a utun device number X", dev_node);
    }



  CLEAR (ctlInfo);
  if (strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name)) >=
      sizeof(ctlInfo.ctl_name))
    {
      msg (M_ERR, "Opening utun: UTUN_CONTROL_NAME too long");
    }

  /* try to open first available utun device if no specific utun is requested */
  if (utunnum == -1)
    {
      for (utunnum=0; utunnum<255; utunnum++)
        {
          fd = utun_open_helper (ctlInfo, utunnum);
          /* Break if the fd is valid,
           * or if early initalization failed (-2) */
          if (fd !=-1)
            break;
        }
    }
  else
    {
      fd = utun_open_helper (ctlInfo, utunnum);
    }

  /* opening an utun device failed */
  tt->fd = fd;

  if (fd < 0)
      return;

  /* Retrieve the assigned interface name. */
  if (getsockopt (fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, utunname, &utunname_len))
   msg (M_ERR | M_ERRNO, "Error retrieving utun interface name");

  tt->actual_name = string_alloc (utunname, NULL);

  msg (M_INFO, "Opened utun device %s", utunname);
  tt->is_utun = true;
}

#endif

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
#ifdef HAVE_NET_IF_UTUN_H
  /* If dev_node does not start start with utun assume regular tun/tap */
  if ((!dev_node && tt->type==DEV_TYPE_TUN) ||
      (dev_node && !strncmp (dev_node, "utun", 4)))
    {

      /* Check if user has specific dev_type tap and forced utun with
         dev-node utun */
      if (tt->type!=DEV_TYPE_TUN)
        msg (M_FATAL, "Cannot use utun devices with --dev-type %s",
             dev_type_string (dev, dev_type));

      /* Try utun first and fall back to normal tun if utun fails
         and dev_node is not specified */
      open_darwin_utun(dev, dev_type, dev_node, tt);

      if (!tt->is_utun)
        {
          if (!dev_node)
            {
              /* No explicit utun and utun failed, try the generic way) */
              msg (M_INFO, "Failed to open utun device. Falling back to /dev/tun device");
              open_tun_generic (dev, dev_type, NULL, true, true, tt);
            }
          else
            {
              /* Specific utun device or generic utun request with no tun
                 fall back failed, consider this a fatal failure */
              msg (M_FATAL, "Cannot open utun device");
            }
        }
    }
  else
#endif
    {

      /* Use plain dev-node tun to select /dev/tun style
       * Unset dev_node variable prior to passing to open_tun_generic to
       * let open_tun_generic pick the first available tun device */

      if (dev_node && strcmp (dev_node, "tun")==0)
        dev_node=NULL;

      open_tun_generic (dev, dev_type, dev_node, true, true, tt);
    }
}

void
close_tun (struct tuntap* tt)
{
  if (tt)
    {
      struct gc_arena gc = gc_new ();
      struct argv argv;
      argv_init (&argv);

      if ( tt->ipv6 && tt->did_ifconfig_ipv6_setup )
	{
	  const char * ifconfig_ipv6_local =
				print_in6_addr (tt->local_ipv6, 0, &gc);

          argv_printf (&argv, "%s delete -inet6 %s",
                              ROUTE_PATH, ifconfig_ipv6_local );
	  argv_msg (M_INFO, &argv);
	  openvpn_execve_check (&argv, NULL, 0, "MacOS X 'remove inet6 route' failed (non-critical)");
	}

      close_tun_generic (tt);
      free (tt);
      argv_reset (&argv);
      gc_free (&gc);
    }
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
#ifdef HAVE_NET_IF_UTUN_H
  if (tt->is_utun)
    return write_tun_header (tt, buf, len);
  else
#endif
    return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
#ifdef HAVE_NET_IF_UTUN_H
  if (tt->is_utun)
    return read_tun_header (tt, buf, len);
  else
#endif
    return read (tt->fd, buf, len);
}

#elif defined(WIN32)

int
tun_read_queue (struct tuntap *tt, int maxsize)
{
  if (tt->reads.iostate == IOSTATE_INITIAL)
    {
      DWORD len;
      BOOL status;
      int err;

      /* reset buf to its initial state */
      tt->reads.buf = tt->reads.buf_init;

      len = maxsize ? maxsize : BLEN (&tt->reads.buf);
      ASSERT (len <= BLEN (&tt->reads.buf));

      /* the overlapped read will signal this event on I/O completion */
      ASSERT (ResetEvent (tt->reads.overlapped.hEvent));

      status = ReadFile(
		      tt->hand,
		      BPTR (&tt->reads.buf),
		      len,
		      &tt->reads.size,
		      &tt->reads.overlapped
		      );

      if (status) /* operation completed immediately? */
	{
	  /* since we got an immediate return, we must signal the event object ourselves */
	  ASSERT (SetEvent (tt->reads.overlapped.hEvent));

	  tt->reads.iostate = IOSTATE_IMMEDIATE_RETURN;
	  tt->reads.status = 0;

	  dmsg (D_WIN32_IO, "WIN32 I/O: TAP Read immediate return [%d,%d]",
	       (int) len,
	       (int) tt->reads.size);	       
	}
      else
	{
	  err = GetLastError (); 
	  if (err == ERROR_IO_PENDING) /* operation queued? */
	    {
	      tt->reads.iostate = IOSTATE_QUEUED;
	      tt->reads.status = err;
	      dmsg (D_WIN32_IO, "WIN32 I/O: TAP Read queued [%d]",
		   (int) len);
	    }
	  else /* error occurred */
	    {
	      struct gc_arena gc = gc_new ();
	      ASSERT (SetEvent (tt->reads.overlapped.hEvent));
	      tt->reads.iostate = IOSTATE_IMMEDIATE_RETURN;
	      tt->reads.status = err;
	      dmsg (D_WIN32_IO, "WIN32 I/O: TAP Read error [%d] : %s",
		   (int) len,
		   strerror_win32 (status, &gc));
	      gc_free (&gc);
	    }
	}
    }
  return tt->reads.iostate;
}

int
tun_write_queue (struct tuntap *tt, struct buffer *buf)
{
  if (tt->writes.iostate == IOSTATE_INITIAL)
    {
      BOOL status;
      int err;
 
      /* make a private copy of buf */
      tt->writes.buf = tt->writes.buf_init;
      tt->writes.buf.len = 0;
      ASSERT (buf_copy (&tt->writes.buf, buf));

      /* the overlapped write will signal this event on I/O completion */
      ASSERT (ResetEvent (tt->writes.overlapped.hEvent));

      status = WriteFile(
			tt->hand,
			BPTR (&tt->writes.buf),
			BLEN (&tt->writes.buf),
			&tt->writes.size,
			&tt->writes.overlapped
			);

      if (status) /* operation completed immediately? */
	{
	  tt->writes.iostate = IOSTATE_IMMEDIATE_RETURN;

	  /* since we got an immediate return, we must signal the event object ourselves */
	  ASSERT (SetEvent (tt->writes.overlapped.hEvent));

	  tt->writes.status = 0;

	  dmsg (D_WIN32_IO, "WIN32 I/O: TAP Write immediate return [%d,%d]",
	       BLEN (&tt->writes.buf),
	       (int) tt->writes.size);	       
	}
      else
	{
	  err = GetLastError (); 
	  if (err == ERROR_IO_PENDING) /* operation queued? */
	    {
	      tt->writes.iostate = IOSTATE_QUEUED;
	      tt->writes.status = err;
	      dmsg (D_WIN32_IO, "WIN32 I/O: TAP Write queued [%d]",
		   BLEN (&tt->writes.buf));
	    }
	  else /* error occurred */
	    {
	      struct gc_arena gc = gc_new ();
	      ASSERT (SetEvent (tt->writes.overlapped.hEvent));
	      tt->writes.iostate = IOSTATE_IMMEDIATE_RETURN;
	      tt->writes.status = err;
	      dmsg (D_WIN32_IO, "WIN32 I/O: TAP Write error [%d] : %s",
		   BLEN (&tt->writes.buf),
		   strerror_win32 (err, &gc));
	      gc_free (&gc);
	    }
	}
    }
  return tt->writes.iostate;
}

int
tun_finalize (
	      HANDLE h,
	      struct overlapped_io *io,
	      struct buffer *buf)
{
  int ret = -1;
  BOOL status;

  switch (io->iostate)
    {
    case IOSTATE_QUEUED:
      status = GetOverlappedResult(
				   h,
				   &io->overlapped,
				   &io->size,
				   FALSE
				   );
      if (status)
	{
	  /* successful return for a queued operation */
	  if (buf)
	    *buf = io->buf;
	  ret = io->size;
	  io->iostate = IOSTATE_INITIAL;
	  ASSERT (ResetEvent (io->overlapped.hEvent));
	  dmsg (D_WIN32_IO, "WIN32 I/O: TAP Completion success [%d]", ret);
	}
      else
	{
	  /* error during a queued operation */
	  ret = -1;
	  if (GetLastError() != ERROR_IO_INCOMPLETE)
	    {
	      /* if no error (i.e. just not finished yet),
		 then DON'T execute this code */
	      io->iostate = IOSTATE_INITIAL;
	      ASSERT (ResetEvent (io->overlapped.hEvent));
	      msg (D_WIN32_IO | M_ERRNO, "WIN32 I/O: TAP Completion error");
	    }
	}
      break;

    case IOSTATE_IMMEDIATE_RETURN:
      io->iostate = IOSTATE_INITIAL;
      ASSERT (ResetEvent (io->overlapped.hEvent));
      if (io->status)
	{
	  /* error return for a non-queued operation */
	  SetLastError (io->status);
	  ret = -1;
	  msg (D_WIN32_IO | M_ERRNO, "WIN32 I/O: TAP Completion non-queued error");
	}
      else
	{
	  /* successful return for a non-queued operation */
	  if (buf)
	    *buf = io->buf;
	  ret = io->size;
	  dmsg (D_WIN32_IO, "WIN32 I/O: TAP Completion non-queued success [%d]", ret);
	}
      break;

    case IOSTATE_INITIAL: /* were we called without proper queueing? */
      SetLastError (ERROR_INVALID_FUNCTION);
      ret = -1;
      dmsg (D_WIN32_IO, "WIN32 I/O: TAP Completion BAD STATE");
      break;

    default:
      ASSERT (0);
    }

  if (buf)
    buf->len = ret;
  return ret;
}

const struct tap_reg *
get_tap_reg (struct gc_arena *gc)
{
  HKEY adapter_key;
  LONG status;
  DWORD len;
  struct tap_reg *first = NULL;
  struct tap_reg *last = NULL;
  int i = 0;

  status = RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			ADAPTER_KEY,
			0,
			KEY_READ,
			&adapter_key);

  if (status != ERROR_SUCCESS)
    msg (M_FATAL, "Error opening registry key: %s", ADAPTER_KEY);

  while (true)
    {
      char enum_name[256];
      char unit_string[256];
      HKEY unit_key;
      char component_id_string[] = "ComponentId";
      char component_id[256];
      char net_cfg_instance_id_string[] = "NetCfgInstanceId";
      char net_cfg_instance_id[256];
      DWORD data_type;

      len = sizeof (enum_name);
      status = RegEnumKeyEx(
			    adapter_key,
			    i,
			    enum_name,
			    &len,
			    NULL,
			    NULL,
			    NULL,
			    NULL);
      if (status == ERROR_NO_MORE_ITEMS)
	break;
      else if (status != ERROR_SUCCESS)
	msg (M_FATAL, "Error enumerating registry subkeys of key: %s",
	     ADAPTER_KEY);

      openvpn_snprintf (unit_string, sizeof(unit_string), "%s\\%s",
			ADAPTER_KEY, enum_name);

      status = RegOpenKeyEx(
			    HKEY_LOCAL_MACHINE,
			    unit_string,
			    0,
			    KEY_READ,
			    &unit_key);

      if (status != ERROR_SUCCESS)
	dmsg (D_REGISTRY, "Error opening registry key: %s", unit_string);
      else
	{
	  len = sizeof (component_id);
	  status = RegQueryValueEx(
				   unit_key,
				   component_id_string,
				   NULL,
				   &data_type,
				   component_id,
				   &len);

	  if (status != ERROR_SUCCESS || data_type != REG_SZ)
	    dmsg (D_REGISTRY, "Error opening registry key: %s\\%s",
		 unit_string, component_id_string);
	  else
	    {	      
	      len = sizeof (net_cfg_instance_id);
	      status = RegQueryValueEx(
				       unit_key,
				       net_cfg_instance_id_string,
				       NULL,
				       &data_type,
				       net_cfg_instance_id,
				       &len);

	      if (status == ERROR_SUCCESS && data_type == REG_SZ)
		{
		  if (!strcmp (component_id, TAP_WIN_COMPONENT_ID))
		    {
		      struct tap_reg *reg;
		      ALLOC_OBJ_CLEAR_GC (reg, struct tap_reg, gc);
		      reg->guid = string_alloc (net_cfg_instance_id, gc);
		      
		      /* link into return list */
		      if (!first)
			first = reg;
		      if (last)
			last->next = reg;
		      last = reg;
		    }
		}
	    }
	  RegCloseKey (unit_key);
	}
      ++i;
    }

  RegCloseKey (adapter_key);
  return first;
}

const struct panel_reg *
get_panel_reg (struct gc_arena *gc)
{
  LONG status;
  HKEY network_connections_key;
  DWORD len;
  struct panel_reg *first = NULL;
  struct panel_reg *last = NULL;
  int i = 0;

  status = RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			NETWORK_CONNECTIONS_KEY,
			0,
			KEY_READ,
			&network_connections_key);

  if (status != ERROR_SUCCESS)
    msg (M_FATAL, "Error opening registry key: %s", NETWORK_CONNECTIONS_KEY);

  while (true)
    {
      char enum_name[256];
      char connection_string[256];
      HKEY connection_key;
      WCHAR name_data[256];
      DWORD name_type;
      const WCHAR name_string[] = L"Name";

      len = sizeof (enum_name);
      status = RegEnumKeyEx(
			    network_connections_key,
			    i,
			    enum_name,
			    &len,
			    NULL,
			    NULL,
			    NULL,
			    NULL);
      if (status == ERROR_NO_MORE_ITEMS)
	break;
      else if (status != ERROR_SUCCESS)
	msg (M_FATAL, "Error enumerating registry subkeys of key: %s",
	     NETWORK_CONNECTIONS_KEY);

      openvpn_snprintf (connection_string, sizeof(connection_string),
			"%s\\%s\\Connection",
			NETWORK_CONNECTIONS_KEY, enum_name);

      status = RegOpenKeyEx(
			    HKEY_LOCAL_MACHINE,
			    connection_string,
			    0,
			    KEY_READ,
			    &connection_key);

      if (status != ERROR_SUCCESS)
	dmsg (D_REGISTRY, "Error opening registry key: %s", connection_string);
      else
	{
	  len = sizeof (name_data);
	  status = RegQueryValueExW(
				   connection_key,
				   name_string,
				   NULL,
				   &name_type,
				   (LPBYTE) name_data,
				   &len);

	  if (status != ERROR_SUCCESS || name_type != REG_SZ)
	    dmsg (D_REGISTRY, "Error opening registry key: %s\\%s\\%s",
		 NETWORK_CONNECTIONS_KEY, connection_string, name_string);
	  else
	    {
              int n;
              LPSTR name;
	      struct panel_reg *reg;

	      ALLOC_OBJ_CLEAR_GC (reg, struct panel_reg, gc);
              n = WideCharToMultiByte (CP_UTF8, 0, name_data, -1, NULL, 0, NULL, NULL);
              name = gc_malloc (n, false, gc);
              WideCharToMultiByte (CP_UTF8, 0, name_data, -1, name, n, NULL, NULL);
              reg->name = name;
	      reg->guid = string_alloc (enum_name, gc);
		      
	      /* link into return list */
	      if (!first)
		first = reg;
	      if (last)
		last->next = reg;
	      last = reg;
	    }
	  RegCloseKey (connection_key);
	}
      ++i;
    }

  RegCloseKey (network_connections_key);

  return first;
}

/*
 * Check that two addresses are part of the same 255.255.255.252 subnet.
 */
void
verify_255_255_255_252 (in_addr_t local, in_addr_t remote)
{
  struct gc_arena gc = gc_new ();
  const unsigned int mask = 3;
  const char *err = NULL;

  if (local == remote)
    {
      err = "must be different";
      goto error;
    }
  if ((local & (~mask)) != (remote & (~mask)))
    {
      err = "must exist within the same 255.255.255.252 subnet.  This is a limitation of --dev tun when used with the TAP-WIN32 driver";
      goto error;
    }
  if ((local & mask) == 0
      || (local & mask) == 3
      || (remote & mask) == 0
      || (remote & mask) == 3)
    {
      err = "cannot use the first or last address within a given 255.255.255.252 subnet.  This is a limitation of --dev tun when used with the TAP-WIN32 driver";
      goto error;
    }

  gc_free (&gc);
  return;

 error:
  msg (M_FATAL, "There is a problem in your selection of --ifconfig endpoints [local=%s, remote=%s].  The local and remote VPN endpoints %s.  Try '" PACKAGE " --show-valid-subnets' option for more info.",
       print_in_addr_t (local, 0, &gc),
       print_in_addr_t (remote, 0, &gc),
       err);
  gc_free (&gc);
}

void show_valid_win32_tun_subnets (void)
{
  int i;
  int col = 0;

  printf ("On Windows, point-to-point IP support (i.e. --dev tun)\n");
  printf ("is emulated by the TAP-Windows driver.  The major limitation\n");
  printf ("imposed by this approach is that the --ifconfig local and\n");
  printf ("remote endpoints must be part of the same 255.255.255.252\n");
  printf ("subnet.  The following list shows examples of endpoint\n");
  printf ("pairs which satisfy this requirement.  Only the final\n");
  printf ("component of the IP address pairs is at issue.\n\n");
  printf ("As an example, the following option would be correct:\n");
  printf ("    --ifconfig 10.7.0.5 10.7.0.6 (on host A)\n");
  printf ("    --ifconfig 10.7.0.6 10.7.0.5 (on host B)\n");
  printf ("because [5,6] is part of the below list.\n\n");

  for (i = 0; i < 256; i += 4)
    {
      printf("[%3d,%3d] ", i+1, i+2);
      if (++col > 4)
	{
	  col = 0;
	  printf ("\n");
	}
    }
  if (col)
    printf ("\n");
}

void
show_tap_win_adapters (int msglev, int warnlev)
{
  struct gc_arena gc = gc_new ();

  bool warn_panel_null = false;
  bool warn_panel_dup = false;
  bool warn_tap_dup = false;

  int links;

  const struct tap_reg *tr;
  const struct tap_reg *tr1;
  const struct panel_reg *pr;

  const struct tap_reg *tap_reg = get_tap_reg (&gc);
  const struct panel_reg *panel_reg = get_panel_reg (&gc);

  msg (msglev, "Available TAP-WIN32 adapters [name, GUID]:");

  /* loop through each TAP-Windows adapter registry entry */
  for (tr = tap_reg; tr != NULL; tr = tr->next)
    {
      links = 0;

      /* loop through each network connections entry in the control panel */
      for (pr = panel_reg; pr != NULL; pr = pr->next)
	{
	  if (!strcmp (tr->guid, pr->guid))
	    {
	      msg (msglev, "'%s' %s", pr->name, tr->guid);
	      ++links;
	    }
	}

      if (links > 1)
	{
	  warn_panel_dup = true;
	}
      else if (links == 0)
	{
	  /* a TAP adapter exists without a link from the network
	     connections control panel */
	  warn_panel_null = true;
	  msg (msglev, "[NULL] %s", tr->guid);
	}
    }

  /* check for TAP-Windows adapter duplicated GUIDs */
  for (tr = tap_reg; tr != NULL; tr = tr->next)
    {
      for (tr1 = tap_reg; tr1 != NULL; tr1 = tr1->next)
	{
	  if (tr != tr1 && !strcmp (tr->guid, tr1->guid))
	    warn_tap_dup = true;
	}
    }

  /* warn on registry inconsistencies */
  if (warn_tap_dup)
    msg (warnlev, "WARNING: Some TAP-Windows adapters have duplicate GUIDs");

  if (warn_panel_dup)
    msg (warnlev, "WARNING: Some TAP-Windows adapters have duplicate links from the Network Connections control panel");

  if (warn_panel_null)
    msg (warnlev, "WARNING: Some TAP-Windows adapters have no link from the Network Connections control panel");

  gc_free (&gc);
}

/*
 * Confirm that GUID is a TAP-Windows adapter.
 */
static bool
is_tap_win (const char *guid, const struct tap_reg *tap_reg)
{
  const struct tap_reg *tr;

  for (tr = tap_reg; tr != NULL; tr = tr->next)
    {
      if (guid && !strcmp (tr->guid, guid))
	return true;
    }

  return false;
}

static const char *
guid_to_name (const char *guid, const struct panel_reg *panel_reg)
{
  const struct panel_reg *pr;

  for (pr = panel_reg; pr != NULL; pr = pr->next)
    {
      if (guid && !strcmp (pr->guid, guid))
	return pr->name;
    }

  return NULL;
}

static const char *
name_to_guid (const char *name, const struct tap_reg *tap_reg, const struct panel_reg *panel_reg)
{
  const struct panel_reg *pr;

  for (pr = panel_reg; pr != NULL; pr = pr->next)
    {
      if (name && !strcmp (pr->name, name) && is_tap_win (pr->guid, tap_reg))
	return pr->guid;
    }

  return NULL;
}

static void
at_least_one_tap_win (const struct tap_reg *tap_reg)
{
  if (!tap_reg)
    msg (M_FATAL, "There are no TAP-Windows adapters on this system.  You should be able to create a TAP-Windows adapter by going to Start -> All Programs -> TAP-Windows -> Utilities -> Add a new TAP-Windows virtual ethernet adapter.");
}

/*
 * Get an adapter GUID and optional actual_name from the 
 * registry for the TAP device # = device_number.
 */
static const char *
get_unspecified_device_guid (const int device_number,
		             char *actual_name,
		             int actual_name_size,
			     const struct tap_reg *tap_reg_src,
			     const struct panel_reg *panel_reg_src,
		             struct gc_arena *gc)
{
  const struct tap_reg *tap_reg = tap_reg_src;
  struct buffer ret = clear_buf ();
  struct buffer actual = clear_buf ();
  int i;

  ASSERT (device_number >= 0);

  /* Make sure we have at least one TAP adapter */
  if (!tap_reg)
    return NULL;

  /* The actual_name output buffer may be NULL */
  if (actual_name)
    {
      ASSERT (actual_name_size > 0);
      buf_set_write (&actual, actual_name, actual_name_size);
    }

  /* Move on to specified device number */
  for (i = 0; i < device_number; i++)
    {
      tap_reg = tap_reg->next;
      if (!tap_reg)
	return NULL;
    }

  /* Save Network Panel name (if exists) in actual_name */
  if (actual_name)
    {
      const char *act = guid_to_name (tap_reg->guid, panel_reg_src);
      if (act)
	buf_printf (&actual, "%s", act);
      else
	buf_printf (&actual, "%s", tap_reg->guid);
    }

  /* Save GUID for return value */
  ret = alloc_buf_gc (256, gc);
  buf_printf (&ret, "%s", tap_reg->guid);
  return BSTR (&ret);
}

/*
 * Lookup a --dev-node adapter name in the registry
 * returning the GUID and optional actual_name.
 */
static const char *
get_device_guid (const char *name,
		 char *actual_name,
		 int actual_name_size,
		 const struct tap_reg *tap_reg,
		 const struct panel_reg *panel_reg,
		 struct gc_arena *gc)
{
  struct buffer ret = alloc_buf_gc (256, gc);
  struct buffer actual = clear_buf ();

  /* Make sure we have at least one TAP adapter */
  if (!tap_reg)
    return NULL;

  /* The actual_name output buffer may be NULL */
  if (actual_name)
    {
      ASSERT (actual_name_size > 0);
      buf_set_write (&actual, actual_name, actual_name_size);
    }

  /* Check if GUID was explicitly specified as --dev-node parameter */
  if (is_tap_win (name, tap_reg))
    {
      const char *act = guid_to_name (name, panel_reg);
      buf_printf (&ret, "%s", name);
      if (act)
	buf_printf (&actual, "%s", act);
      else
	buf_printf (&actual, "%s", name);
      return BSTR (&ret);
    }

  /* Lookup TAP adapter in network connections list */
  {
    const char *guid = name_to_guid (name, tap_reg, panel_reg);
    if (guid)
      {
	buf_printf (&actual, "%s", name);
	buf_printf (&ret, "%s", guid);
	return BSTR (&ret);
      }
  }

  return NULL;
}

/*
 * Get adapter info list
 */
const IP_ADAPTER_INFO *
get_adapter_info_list (struct gc_arena *gc)
{
  ULONG size = 0;
  IP_ADAPTER_INFO *pi = NULL;
  DWORD status;

  if ((status = GetAdaptersInfo (NULL, &size)) != ERROR_BUFFER_OVERFLOW)
    {
      msg (M_INFO, "GetAdaptersInfo #1 failed (status=%u) : %s",
	   (unsigned int)status,
	   strerror_win32 (status, gc));
    }
  else
    {
      pi = (PIP_ADAPTER_INFO) gc_malloc (size, false, gc);
      if ((status = GetAdaptersInfo (pi, &size)) == NO_ERROR)
	return pi;
      else
	{
	  msg (M_INFO, "GetAdaptersInfo #2 failed (status=%u) : %s",
	       (unsigned int)status,
	       strerror_win32 (status, gc));
	}
    }
  return pi;
}

const IP_PER_ADAPTER_INFO *
get_per_adapter_info (const DWORD index, struct gc_arena *gc)
{
  ULONG size = 0;
  IP_PER_ADAPTER_INFO *pi = NULL;
  DWORD status;

  if (index != TUN_ADAPTER_INDEX_INVALID)
    {
      if ((status = GetPerAdapterInfo (index, NULL, &size)) != ERROR_BUFFER_OVERFLOW)
	{
	  msg (M_INFO, "GetPerAdapterInfo #1 failed (status=%u) : %s",
	       (unsigned int)status,
	       strerror_win32 (status, gc));
	}
      else
	{
	  pi = (PIP_PER_ADAPTER_INFO) gc_malloc (size, false, gc);
	  if ((status = GetPerAdapterInfo ((ULONG)index, pi, &size)) == ERROR_SUCCESS)
	    return pi;
	  else
	    {
	      msg (M_INFO, "GetPerAdapterInfo #2 failed (status=%u) : %s",
		   (unsigned int)status,
		   strerror_win32 (status, gc));
	    }
	}
    }
  return pi;
}

static const IP_INTERFACE_INFO *
get_interface_info_list (struct gc_arena *gc)
{
  ULONG size = 0;
  IP_INTERFACE_INFO *ii = NULL;
  DWORD status;

  if ((status = GetInterfaceInfo (NULL, &size)) != ERROR_INSUFFICIENT_BUFFER)
    {
      msg (M_INFO, "GetInterfaceInfo #1 failed (status=%u) : %s",
	   (unsigned int)status,
	   strerror_win32 (status, gc));
    }
  else
    {
      ii = (PIP_INTERFACE_INFO) gc_malloc (size, false, gc);
      if ((status = GetInterfaceInfo (ii, &size)) == NO_ERROR)
	return ii;
      else
	{
	  msg (M_INFO, "GetInterfaceInfo #2 failed (status=%u) : %s",
	       (unsigned int)status,
	       strerror_win32 (status, gc));
	}
    }
  return ii;
}

static const IP_ADAPTER_INDEX_MAP *
get_interface_info (DWORD index, struct gc_arena *gc)
{
  const IP_INTERFACE_INFO *list = get_interface_info_list (gc);
  if (list)
    {
      int i;
      for (i = 0; i < list->NumAdapters; ++i)
	{
	  const IP_ADAPTER_INDEX_MAP *inter = &list->Adapter[i];
	  if (index == inter->Index)
	    return inter;
	}
    }
  return NULL;
}

/*
 * Given an adapter index, return a pointer to the
 * IP_ADAPTER_INFO structure for that adapter.
 */

const IP_ADAPTER_INFO *
get_adapter (const IP_ADAPTER_INFO *ai, DWORD index)
{
  if (ai && index != TUN_ADAPTER_INDEX_INVALID)
    {
      const IP_ADAPTER_INFO *a;

      /* find index in the linked list */
      for (a = ai; a != NULL; a = a->Next)
	{
	  if (a->Index == index)
	    return a;
	}
    }
  return NULL;
}

const IP_ADAPTER_INFO *
get_adapter_info (DWORD index, struct gc_arena *gc)
{
  return get_adapter (get_adapter_info_list (gc), index);
}

static int
get_adapter_n_ip_netmask (const IP_ADAPTER_INFO *ai)
{
  if (ai)
    {
      int n = 0;
      const IP_ADDR_STRING *ip = &ai->IpAddressList;

      while (ip)
	{
	  ++n;
	  ip = ip->Next;
	}
      return n;
    }
  else
    return 0;
}

static bool
get_adapter_ip_netmask (const IP_ADAPTER_INFO *ai, const int n, in_addr_t *ip, in_addr_t *netmask)
{
  bool ret = false;
  *ip = 0;
  *netmask = 0;

  if (ai)
    {
      const IP_ADDR_STRING *iplist = &ai->IpAddressList;
      int i = 0;

      while (iplist)
	{
	  if (i == n)
	    break;
	  ++i;
	  iplist = iplist->Next;
	}

      if (iplist)
	{
	  const unsigned int getaddr_flags = GETADDR_HOST_ORDER;
	  const char *ip_str = iplist->IpAddress.String;
	  const char *netmask_str = iplist->IpMask.String;
	  bool succeed1 = false;
	  bool succeed2 = false;

	  if (ip_str && netmask_str && strlen (ip_str) && strlen (netmask_str))
	    {
	      *ip = getaddr (getaddr_flags, ip_str, 0, &succeed1, NULL);
	      *netmask = getaddr (getaddr_flags, netmask_str, 0, &succeed2, NULL);
	      ret = (succeed1 == true && succeed2 == true);
	    }
	}
    }

  return ret;
}

static bool
test_adapter_ip_netmask (const IP_ADAPTER_INFO *ai, const in_addr_t ip, const in_addr_t netmask)
{
  if (ai)
    {
      in_addr_t ip_adapter = 0;
      in_addr_t netmask_adapter = 0;
      const bool status = get_adapter_ip_netmask (ai, 0, &ip_adapter, &netmask_adapter);
      return (status && ip_adapter == ip && netmask_adapter == netmask);
    }
  else
    return false;
}

const IP_ADAPTER_INFO *
get_tun_adapter (const struct tuntap *tt, const IP_ADAPTER_INFO *list)
{
  if (list && tt)
    return get_adapter (list, tt->adapter_index);
  else
    return NULL;
}

bool
is_adapter_up (const struct tuntap *tt, const IP_ADAPTER_INFO *list)
{
  int i;
  bool ret = false;

  const IP_ADAPTER_INFO *ai = get_tun_adapter (tt, list);

  if (ai)
    {
      const int n = get_adapter_n_ip_netmask (ai);

      /* loop once for every IP/netmask assigned to adapter */
      for (i = 0; i < n; ++i)
	{
	  in_addr_t ip, netmask;
	  if (get_adapter_ip_netmask (ai, i, &ip, &netmask))
	    {
	      if (tt->local && tt->adapter_netmask)
		{
		  /* wait for our --ifconfig parms to match the actual adapter parms */
		  if (tt->local == ip && tt->adapter_netmask == netmask)
		    ret = true;
		}
	      else
		{
		  /* --ifconfig was not defined, maybe using a real DHCP server */
		  if (ip && netmask)
		    ret = true;
		}
	    }
	}
    }
  else
    ret = true; /* this can occur when TAP adapter is bridged */

  return ret;
}

bool
is_ip_in_adapter_subnet (const IP_ADAPTER_INFO *ai, const in_addr_t ip, in_addr_t *highest_netmask)
{
  int i;
  bool ret = false;

  if (highest_netmask)
    *highest_netmask = 0;

  if (ai)
    {
      const int n = get_adapter_n_ip_netmask (ai);
      for (i = 0; i < n; ++i)
	{
	  in_addr_t adapter_ip, adapter_netmask;
	  if (get_adapter_ip_netmask (ai, i, &adapter_ip, &adapter_netmask))
	    {
	      if (adapter_ip && adapter_netmask && (ip & adapter_netmask) == (adapter_ip & adapter_netmask))
		{
		  if (highest_netmask && adapter_netmask > *highest_netmask)
		    *highest_netmask = adapter_netmask;
		  ret = true;
		}
	    }
	}
    }
  return ret;
}

DWORD
adapter_index_of_ip (const IP_ADAPTER_INFO *list,
		     const in_addr_t ip,
		     int *count,
		     in_addr_t *netmask)
{
  struct gc_arena gc = gc_new ();
  DWORD ret = TUN_ADAPTER_INDEX_INVALID;
  in_addr_t highest_netmask = 0;
  bool first = true;

  if (count)
    *count = 0;

  while (list)
    {
      in_addr_t hn;

      if (is_ip_in_adapter_subnet (list, ip, &hn))
	{
	  if (first || hn > highest_netmask)
	    {
	      highest_netmask = hn;
	      if (count)
		*count = 1;
	      ret = list->Index;
	      first = false;
	    }
	  else if (hn == highest_netmask)
	    {
	      if (count)
		++*count;
	    }
	}
      list = list->Next;
    }

  dmsg (D_ROUTE_DEBUG, "DEBUG: IP Locate: ip=%s nm=%s index=%d count=%d",
       print_in_addr_t (ip, 0, &gc),
       print_in_addr_t (highest_netmask, 0, &gc),
       (int)ret,
       count ? *count : -1);

  if (ret == TUN_ADAPTER_INDEX_INVALID && count)
    *count = 0;

  if (netmask)
    *netmask = highest_netmask;

  gc_free (&gc);
  return ret;
}

/*
 * Given an adapter index, return true if the adapter
 * is DHCP disabled.
 */

#define DHCP_STATUS_UNDEF     0
#define DHCP_STATUS_ENABLED   1
#define DHCP_STATUS_DISABLED  2

static int
dhcp_status (DWORD index)
{
  struct gc_arena gc = gc_new ();
  int ret = DHCP_STATUS_UNDEF;
  if (index != TUN_ADAPTER_INDEX_INVALID)
    {
      const IP_ADAPTER_INFO *ai = get_adapter_info (index, &gc);

      if (ai)
	{
	  if (ai->DhcpEnabled)
	    ret = DHCP_STATUS_ENABLED;
	  else
	    ret = DHCP_STATUS_DISABLED;
	}
    }
  gc_free (&gc);
  return ret;
}

/*
 * Delete all temporary address/netmask pairs which were added
 * to adapter (given by index) by previous calls to AddIPAddress.
 */
static void
delete_temp_addresses (DWORD index)
{
  struct gc_arena gc = gc_new ();
  const IP_ADAPTER_INFO *a = get_adapter_info (index, &gc);

  if (a)
    {
      const IP_ADDR_STRING *ip = &a->IpAddressList;
      while (ip)
	{
	  DWORD status;
	  const DWORD context = ip->Context;

	  if ((status = DeleteIPAddress ((ULONG) context)) == NO_ERROR)
	    {
	      msg (M_INFO, "Successfully deleted previously set dynamic IP/netmask: %s/%s",
		   ip->IpAddress.String,
		   ip->IpMask.String);
	    }
	  else
	    {
	      const char *empty = "0.0.0.0";
	      if (strcmp (ip->IpAddress.String, empty)
		  || strcmp (ip->IpMask.String, empty))
		msg (M_INFO, "NOTE: could not delete previously set dynamic IP/netmask: %s/%s (status=%u)",
		     ip->IpAddress.String,
		     ip->IpMask.String,
		     (unsigned int)status);
	    }
	  ip = ip->Next;
	}
    }
  gc_free (&gc);
}

/*
 * Get interface index for use with IP Helper API functions.
 */
static DWORD
get_adapter_index_method_1 (const char *guid)
{
  DWORD index;
  ULONG aindex;
  wchar_t wbuf[256];
  _snwprintf (wbuf, SIZE (wbuf), L"\\DEVICE\\TCPIP_%S", guid);
  wbuf [SIZE(wbuf) - 1] = 0;
  if (GetAdapterIndex (wbuf, &aindex) != NO_ERROR)
    index = TUN_ADAPTER_INDEX_INVALID;
  else
    index = (DWORD)aindex;
  return index;
}

static DWORD
get_adapter_index_method_2 (const char *guid)
{
  struct gc_arena gc = gc_new ();
  DWORD index = TUN_ADAPTER_INDEX_INVALID;

  const IP_ADAPTER_INFO *list = get_adapter_info_list (&gc);

  while (list)
    {
      if (!strcmp (guid, list->AdapterName))
	{
	  index = list->Index;
	  break;
	}
      list = list->Next;
    }

  gc_free (&gc);
  return index;
}

static DWORD
get_adapter_index (const char *guid)
{
  DWORD index;
  index = get_adapter_index_method_1 (guid);
  if (index == TUN_ADAPTER_INDEX_INVALID)
    index = get_adapter_index_method_2 (guid);
  if (index == TUN_ADAPTER_INDEX_INVALID)
    msg (M_INFO, "NOTE: could not get adapter index for %s", guid);
  return index;
}

static DWORD
get_adapter_index_flexible (const char *name) /* actual name or GUID */
{
  struct gc_arena gc = gc_new ();
  DWORD index;
  index = get_adapter_index_method_1 (name);
  if (index == TUN_ADAPTER_INDEX_INVALID)
    index = get_adapter_index_method_2 (name);
  if (index == TUN_ADAPTER_INDEX_INVALID)
    {
      const struct tap_reg *tap_reg = get_tap_reg (&gc);
      const struct panel_reg *panel_reg = get_panel_reg (&gc);
      const char *guid = name_to_guid (name, tap_reg, panel_reg);
      index = get_adapter_index_method_1 (guid);
      if (index == TUN_ADAPTER_INDEX_INVALID)
	index = get_adapter_index_method_2 (guid);
    }
  if (index == TUN_ADAPTER_INDEX_INVALID)
    msg (M_INFO, "NOTE: could not get adapter index for name/GUID '%s'", name);
  gc_free (&gc);
  return index;
}

/*
 * Return a string representing a PIP_ADDR_STRING
 */
static const char *
format_ip_addr_string (const IP_ADDR_STRING *ip, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (256, gc);
  while (ip)
    {
      buf_printf (&out, "%s", ip->IpAddress.String);
      if (strlen (ip->IpMask.String))
	{
	  buf_printf (&out, "/");
	  buf_printf (&out, "%s", ip->IpMask.String);
	}
      buf_printf (&out, " ");
      ip = ip->Next;
    }
  return BSTR (&out);
}

/*
 * Show info for a single adapter
 */
static void
show_adapter (int msglev, const IP_ADAPTER_INFO *a, struct gc_arena *gc)
{
  msg (msglev, "%s", a->Description);
  msg (msglev, "  Index = %d", (int)a->Index);
  msg (msglev, "  GUID = %s", a->AdapterName);
  msg (msglev, "  IP = %s", format_ip_addr_string (&a->IpAddressList, gc));
  msg (msglev, "  MAC = %s", format_hex_ex (a->Address, a->AddressLength, 0, 1, ":", gc));
  msg (msglev, "  GATEWAY = %s", format_ip_addr_string (&a->GatewayList, gc));
  if (a->DhcpEnabled)
    {
      msg (msglev, "  DHCP SERV = %s", format_ip_addr_string (&a->DhcpServer, gc));
      msg (msglev, "  DHCP LEASE OBTAINED = %s", time_string (a->LeaseObtained, 0, false, gc));
      msg (msglev, "  DHCP LEASE EXPIRES  = %s", time_string (a->LeaseExpires, 0, false, gc));
    }
  if (a->HaveWins)
    {
      msg (msglev, "  PRI WINS = %s", format_ip_addr_string (&a->PrimaryWinsServer, gc));
      msg (msglev, "  SEC WINS = %s", format_ip_addr_string (&a->SecondaryWinsServer, gc));
    }

  {
    const IP_PER_ADAPTER_INFO *pai = get_per_adapter_info (a->Index, gc);
    if (pai)
      {
	msg (msglev, "  DNS SERV = %s", format_ip_addr_string (&pai->DnsServerList, gc));
      }
  }
}

/*
 * Show current adapter list
 */
void
show_adapters (int msglev)
{
  struct gc_arena gc = gc_new ();
  const IP_ADAPTER_INFO *ai = get_adapter_info_list (&gc);

  msg (msglev, "SYSTEM ADAPTER LIST");
  if (ai)
    {
      const IP_ADAPTER_INFO *a;

      /* find index in the linked list */
      for (a = ai; a != NULL; a = a->Next)
	{
	  show_adapter (msglev, a, &gc);
	}
    }
  gc_free (&gc);
}

/*
 * Set a particular TAP-Windows adapter (or all of them if
 * adapter_name == NULL) to allow it to be opened from
 * a non-admin account.  This setting will only persist
 * for the lifetime of the device object.
 */

static void
tap_allow_nonadmin_access_handle (const char *device_path, HANDLE hand)
{
  struct security_attributes sa;
  BOOL status;

  if (!init_security_attributes_allow_all (&sa))
    msg (M_ERR, "Error: init SA failed");

  status = SetKernelObjectSecurity (hand, DACL_SECURITY_INFORMATION, &sa.sd);
  if (!status)
    {
      msg (M_ERRNO, "Error: SetKernelObjectSecurity failed on %s", device_path);
    }
  else
    {
      msg (M_INFO|M_NOPREFIX, "TAP-Windows device: %s [Non-admin access allowed]", device_path);
    }
}

void
tap_allow_nonadmin_access (const char *dev_node)
{
  struct gc_arena gc = gc_new ();
  const struct tap_reg *tap_reg = get_tap_reg (&gc);
  const struct panel_reg *panel_reg = get_panel_reg (&gc);
  const char *device_guid = NULL;
  HANDLE hand;
  char actual_buffer[256];
  char device_path[256];

  at_least_one_tap_win (tap_reg);

  if (dev_node)
    {
      /* Get the device GUID for the device specified with --dev-node. */
      device_guid = get_device_guid (dev_node, actual_buffer, sizeof (actual_buffer), tap_reg, panel_reg, &gc);

      if (!device_guid)
	msg (M_FATAL, "TAP-Windows adapter '%s' not found", dev_node);

      /* Open Windows TAP-Windows adapter */
      openvpn_snprintf (device_path, sizeof(device_path), "%s%s%s",
			USERMODEDEVICEDIR,
			device_guid,
			TAP_WIN_SUFFIX);
      
      hand = CreateFile (
			 device_path,
			 MAXIMUM_ALLOWED,
			 0, /* was: FILE_SHARE_READ */
			 0,
			 OPEN_EXISTING,
			 FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
			 0
			 );

      if (hand == INVALID_HANDLE_VALUE)
	msg (M_ERR, "CreateFile failed on TAP device: %s", device_path);

      tap_allow_nonadmin_access_handle (device_path, hand);
      CloseHandle (hand);
    }
  else 
    {
      int device_number = 0;

      /* Try opening all TAP devices */
      while (true)
	{
	  device_guid = get_unspecified_device_guid (device_number, 
						     actual_buffer, 
						     sizeof (actual_buffer),
						     tap_reg,
						     panel_reg,
						     &gc);

	  if (!device_guid)
	    break;

	  /* Open Windows TAP-Windows adapter */
	  openvpn_snprintf (device_path, sizeof(device_path), "%s%s%s",
			    USERMODEDEVICEDIR,
			    device_guid,
			    TAP_WIN_SUFFIX);

	  hand = CreateFile (
			     device_path,
			     MAXIMUM_ALLOWED,
			     0, /* was: FILE_SHARE_READ */
			     0,
			     OPEN_EXISTING,
			     FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
			     0
			     );

	  if (hand == INVALID_HANDLE_VALUE)
	    msg (M_WARN, "CreateFile failed on TAP device: %s", device_path);
	  else
	    {
	      tap_allow_nonadmin_access_handle (device_path, hand);
	      CloseHandle (hand);
	    }
  
	  device_number++;
	}
    }
  gc_free (&gc);
}

/*
 * DHCP release/renewal
 */
bool
dhcp_release_by_adapter_index(const DWORD adapter_index)
{
  struct gc_arena gc = gc_new ();
  bool ret = false;
  const IP_ADAPTER_INDEX_MAP *inter = get_interface_info (adapter_index, &gc);

  if (inter)
    {
      DWORD status = IpReleaseAddress ((IP_ADAPTER_INDEX_MAP *)inter);
      if (status == NO_ERROR)
	{
	  msg (D_TUNTAP_INFO, "TAP: DHCP address released");
	  ret = true;
	}
      else
	msg (M_WARN, "NOTE: Release of DHCP-assigned IP address lease on TAP-Windows adapter failed: %s (code=%u)",
	     strerror_win32 (status, &gc),
	     (unsigned int)status);
    }

  gc_free (&gc);
  return ret;
}

static bool
dhcp_release (const struct tuntap *tt)
{
  if (tt && tt->options.ip_win32_type == IPW32_SET_DHCP_MASQ && tt->adapter_index != TUN_ADAPTER_INDEX_INVALID)
    return dhcp_release_by_adapter_index (tt->adapter_index);
  else
    return false;
}

bool
dhcp_renew_by_adapter_index (const DWORD adapter_index)
{
  struct gc_arena gc = gc_new ();
  bool ret = false;
  const IP_ADAPTER_INDEX_MAP *inter = get_interface_info (adapter_index, &gc);

  if (inter)
    {
      DWORD status = IpRenewAddress ((IP_ADAPTER_INDEX_MAP *)inter);
      if (status == NO_ERROR)
	{
	  msg (D_TUNTAP_INFO, "TAP: DHCP address renewal succeeded");
	  ret = true;
	}
      else
	msg (M_WARN, "WARNING: Failed to renew DHCP IP address lease on TAP-Windows adapter: %s (code=%u)",
	     strerror_win32 (status, &gc),
	     (unsigned int)status);
    }
  gc_free (&gc);
  return ret;
}

static bool
dhcp_renew (const struct tuntap *tt)
{
  if (tt && tt->options.ip_win32_type == IPW32_SET_DHCP_MASQ && tt->adapter_index != TUN_ADAPTER_INDEX_INVALID)
    return dhcp_renew_by_adapter_index (tt->adapter_index);
  else
    return false;
}

/*
 * netsh functions
 */

static void
netsh_command (const struct argv *a, int n)
{
  int i;
  for (i = 0; i < n; ++i)
    {
      bool status;
      openvpn_sleep (1);
      netcmd_semaphore_lock ();
      argv_msg_prefix (M_INFO, a, "NETSH");
      status = openvpn_execve_check (a, NULL, 0, "ERROR: netsh command failed");
      netcmd_semaphore_release ();
      if (status)
	return;
      openvpn_sleep (4);
    }
  msg (M_FATAL, "NETSH: command failed");
}

void
ipconfig_register_dns (const struct env_set *es)
{
  struct argv argv;
  bool status;
  const char err[] = "ERROR: Windows ipconfig command failed";

  msg (D_TUNTAP_INFO, "Start net commands...");
  netcmd_semaphore_lock ();

  argv_init (&argv);

  argv_printf (&argv, "%s%sc stop dnscache",
	       get_win_sys_path(),
	       WIN_NET_PATH_SUFFIX);
  argv_msg (D_TUNTAP_INFO, &argv);
  status = openvpn_execve_check (&argv, es, 0, err);
  argv_reset(&argv);

  argv_printf (&argv, "%s%sc start dnscache",
	       get_win_sys_path(),
	       WIN_NET_PATH_SUFFIX);
  argv_msg (D_TUNTAP_INFO, &argv);
  status = openvpn_execve_check (&argv, es, 0, err);
  argv_reset(&argv);

  argv_printf (&argv, "%s%sc /flushdns",
	       get_win_sys_path(),
	       WIN_IPCONFIG_PATH_SUFFIX);
  argv_msg (D_TUNTAP_INFO, &argv);
  status = openvpn_execve_check (&argv, es, 0, err);
  argv_reset(&argv);

  argv_printf (&argv, "%s%sc /registerdns",
	       get_win_sys_path(),
	       WIN_IPCONFIG_PATH_SUFFIX);
  argv_msg (D_TUNTAP_INFO, &argv);
  status = openvpn_execve_check (&argv, es, 0, err);
  argv_reset(&argv);

  netcmd_semaphore_release ();
  msg (D_TUNTAP_INFO, "End net commands...");
}

void
ip_addr_string_to_array (in_addr_t *dest, int *dest_len, const IP_ADDR_STRING *src)
{
  int i = 0;
  while (src)
    {
      const unsigned int getaddr_flags = GETADDR_HOST_ORDER;
      const char *ip_str = src->IpAddress.String;
      in_addr_t ip = 0;
      bool succeed = false;

      if (i >= *dest_len)
	break;
      if (!ip_str || !strlen (ip_str))
	break;

      ip = getaddr (getaddr_flags, ip_str, 0, &succeed, NULL);
      if (!succeed)
	break;
      dest[i++] = ip;

      src = src->Next;
    }
  *dest_len = i;

#if 0
 {
   struct gc_arena gc = gc_new ();
   msg (M_INFO, "ip_addr_string_to_array [%d]", *dest_len);
   for (i = 0; i < *dest_len; ++i)
     {
       msg (M_INFO, "%s", print_in_addr_t (dest[i], 0, &gc));
     }
   gc_free (&gc);
 }
#endif
}

static bool
ip_addr_one_to_one (const in_addr_t *a1, const int a1len, const IP_ADDR_STRING *ias)
{
  in_addr_t a2[8];
  int a2len = SIZE(a2);
  int i;

  ip_addr_string_to_array (a2, &a2len, ias);
  /*msg (M_INFO, "a1len=%d a2len=%d", a1len, a2len);*/
  if (a1len != a2len)
    return false;

  for (i = 0; i < a1len; ++i)
    {
      if (a1[i] != a2[i])
	return false;
    }
  return true;
}

static bool
ip_addr_member_of (const in_addr_t addr, const IP_ADDR_STRING *ias)
{
  in_addr_t aa[8];
  int len = SIZE(aa);
  int i;

  ip_addr_string_to_array (aa, &len, ias);
  for (i = 0; i < len; ++i)
    {
      if (addr == aa[i])
	return true;
    }
  return false;
}

static void
netsh_ifconfig_options (const char *type,
			const in_addr_t *addr_list,
			const int addr_len,
			const IP_ADDR_STRING *current,
			const char *flex_name,
			const bool test_first)
{
  struct gc_arena gc = gc_new ();
  struct argv argv = argv_new ();
  bool delete_first = false;

  /* first check if we should delete existing DNS/WINS settings from TAP interface */
  if (test_first)
    {
      if (!ip_addr_one_to_one (addr_list, addr_len, current))
	delete_first = true;
    }
  else
    delete_first = true;
  
  /* delete existing DNS/WINS settings from TAP interface */
  if (delete_first)
    {
      argv_printf (&argv, "%s%sc interface ip delete %s %s all",
		   get_win_sys_path(),
		   NETSH_PATH_SUFFIX,
		   type,
		   flex_name);
      netsh_command (&argv, 2);
    }

  /* add new DNS/WINS settings to TAP interface */
  {
    int count = 0;
    int i;
    for (i = 0; i < addr_len; ++i)
      {
	if (delete_first || !test_first || !ip_addr_member_of (addr_list[i], current))
	  {
	    const char *fmt = count ?
	        "%s%sc interface ip add %s %s %s"
	      : "%s%sc interface ip set %s %s static %s";

	    argv_printf (&argv, fmt,
			 get_win_sys_path(),
			 NETSH_PATH_SUFFIX,
			 type,
			 flex_name,
			 print_in_addr_t (addr_list[i], 0, &gc));
	    netsh_command (&argv, 2);
	  
	    ++count;
	  }
	else
	  {
	    msg (M_INFO, "NETSH: \"%s\" %s %s [already set]",
		 flex_name,
		 type,
		 print_in_addr_t (addr_list[i], 0, &gc));
	  }
      }
  }

  argv_reset (&argv);
  gc_free (&gc);
}

static void
init_ip_addr_string2 (IP_ADDR_STRING *dest, const IP_ADDR_STRING *src1, const IP_ADDR_STRING *src2)
{
  CLEAR (dest[0]);
  CLEAR (dest[1]);
  if (src1)
    {
      dest[0] = *src1;
      dest[0].Next = NULL;
    }
  if (src2)
    {
      dest[1] = *src2;
      dest[0].Next = &dest[1];
      dest[1].Next = NULL;
    }
}

static void
netsh_ifconfig (const struct tuntap_options *to,
		const char *flex_name,
		const in_addr_t ip,
		const in_addr_t netmask,
		const unsigned int flags)
{
  struct gc_arena gc = gc_new ();
  struct argv argv = argv_new ();
  const IP_ADAPTER_INFO *ai = NULL;
  const IP_PER_ADAPTER_INFO *pai = NULL;

  if (flags & NI_TEST_FIRST)
    {
      const IP_ADAPTER_INFO *list = get_adapter_info_list (&gc);
      const int index = get_adapter_index_flexible (flex_name);
      ai = get_adapter (list, index);
      pai = get_per_adapter_info (index, &gc);
    }

  if (flags & NI_IP_NETMASK)
    {
      if (test_adapter_ip_netmask (ai, ip, netmask))
	{
	  msg (M_INFO, "NETSH: \"%s\" %s/%s [already set]",
	       flex_name,
	       print_in_addr_t (ip, 0, &gc),
	       print_in_addr_t (netmask, 0, &gc));
	}
      else
	{
	  /* example: netsh interface ip set address my-tap static 10.3.0.1 255.255.255.0 */
	  argv_printf (&argv, "%s%sc interface ip set address %s static %s %s",
		       get_win_sys_path(),
		       NETSH_PATH_SUFFIX,
		       flex_name,
		       print_in_addr_t (ip, 0, &gc),
		       print_in_addr_t (netmask, 0, &gc));

	  netsh_command (&argv, 4);
	}
    }

  /* set WINS/DNS options */
  if (flags & NI_OPTIONS)
    {
      IP_ADDR_STRING wins[2];
      CLEAR (wins[0]);
      CLEAR (wins[1]);

      netsh_ifconfig_options ("dns",
			      to->dns,
			      to->dns_len,
			      pai ? &pai->DnsServerList : NULL,
			      flex_name,
			      BOOL_CAST (flags & NI_TEST_FIRST));
      if (ai && ai->HaveWins)
	init_ip_addr_string2 (wins, &ai->PrimaryWinsServer, &ai->SecondaryWinsServer);

      netsh_ifconfig_options ("wins",
			      to->wins,
			      to->wins_len,
			      ai ? wins : NULL,
			      flex_name,
			      BOOL_CAST (flags & NI_TEST_FIRST));
    }
  
  argv_reset (&argv);
  gc_free (&gc);
}

static void
netsh_enable_dhcp (const struct tuntap_options *to,
		   const char *actual_name)
{
  struct argv argv;
  argv_init (&argv);

  /* example: netsh interface ip set address my-tap dhcp */
  argv_printf (&argv,
	      "%s%sc interface ip set address %s dhcp",
	       get_win_sys_path(),
	       NETSH_PATH_SUFFIX,
	       actual_name);

  netsh_command (&argv, 4);

  argv_reset (&argv);
}

/*
 * Return a TAP name for netsh commands.
 */
static const char *
netsh_get_id (const char *dev_node, struct gc_arena *gc)
{
  const struct tap_reg *tap_reg = get_tap_reg (gc);
  const struct panel_reg *panel_reg = get_panel_reg (gc);
  struct buffer actual = alloc_buf_gc (256, gc);
  const char *guid;

  at_least_one_tap_win (tap_reg);

  if (dev_node)
    {
      guid = get_device_guid (dev_node, BPTR (&actual), BCAP (&actual), tap_reg, panel_reg, gc);
    }
  else
    {
      guid = get_unspecified_device_guid (0, BPTR (&actual), BCAP (&actual), tap_reg, panel_reg, gc);

      if (get_unspecified_device_guid (1, NULL, 0, tap_reg, panel_reg, gc)) /* ambiguous if more than one TAP-Windows adapter */
	guid = NULL;
    }

  if (!guid)
    return "NULL";         /* not found */
  else if (strcmp (BPTR (&actual), "NULL"))
    return BPTR (&actual); /* control panel name */
  else
    return guid;           /* no control panel name, return GUID instead */
}

/*
 * Called iteratively on TAP-Windows wait-for-initialization polling loop
 */
void
tun_standby_init (struct tuntap *tt)
{
  tt->standby_iter = 0;
}

bool
tun_standby (struct tuntap *tt)
{
  bool ret = true;
  ++tt->standby_iter;
  if (tt->options.ip_win32_type == IPW32_SET_ADAPTIVE)
    {
      if (tt->standby_iter == IPW32_SET_ADAPTIVE_TRY_NETSH)
	{
	  msg (M_INFO, "NOTE: now trying netsh (this may take some time)");
	  netsh_ifconfig (&tt->options,
			  tt->actual_name,
			  tt->local,
			  tt->adapter_netmask,
			  NI_TEST_FIRST|NI_IP_NETMASK|NI_OPTIONS);
	}
      else if (tt->standby_iter >= IPW32_SET_ADAPTIVE_TRY_NETSH*2)
	{
	  ret = false;
	}
    }
  return ret;
}

/*
 * Convert DHCP options from the command line / config file
 * into a raw DHCP-format options string.
 */

static void
write_dhcp_u8 (struct buffer *buf, const int type, const int data, bool *error)
{
  if (!buf_safe (buf, 3))
    {
      *error = true;
      msg (M_WARN, "write_dhcp_u8: buffer overflow building DHCP options");
      return;
    }
  buf_write_u8 (buf, type);
  buf_write_u8 (buf, 1);
  buf_write_u8 (buf, data);
}

static void
write_dhcp_u32_array (struct buffer *buf, const int type, const uint32_t *data, const unsigned int len, bool *error)
{
  if (len > 0)
    {
      int i;
      const int size = len * sizeof (uint32_t);

      if (!buf_safe (buf, 2 + size))
	{
	  *error = true;
	  msg (M_WARN, "write_dhcp_u32_array: buffer overflow building DHCP options");
	  return;
	}
      if (size < 1 || size > 255)
	{
	  *error = true;
	  msg (M_WARN, "write_dhcp_u32_array: size (%d) must be > 0 and <= 255", size);
	  return;
	}
      buf_write_u8 (buf, type);
      buf_write_u8 (buf, size);
      for (i = 0; i < len; ++i)
	buf_write_u32 (buf, data[i]);
    }
}

static void
write_dhcp_str (struct buffer *buf, const int type, const char *str, bool *error)
{
  const int len = strlen (str);
  if (!buf_safe (buf, 2 + len))
    {
      *error = true;
      msg (M_WARN, "write_dhcp_str: buffer overflow building DHCP options");
      return;
    }
  if (len < 1 || len > 255)
    {
      *error = true;
      msg (M_WARN, "write_dhcp_str: string '%s' must be > 0 bytes and <= 255 bytes", str);
      return;
    }
  buf_write_u8 (buf, type);
  buf_write_u8 (buf, len);
  buf_write (buf, str, len);
}

static bool
build_dhcp_options_string (struct buffer *buf, const struct tuntap_options *o)
{
  bool error = false;
  if (o->domain)
    write_dhcp_str (buf, 15, o->domain, &error);

  if (o->netbios_scope)
    write_dhcp_str (buf, 47, o->netbios_scope, &error);

  if (o->netbios_node_type)
    write_dhcp_u8 (buf, 46, o->netbios_node_type, &error);

  write_dhcp_u32_array (buf, 6, (uint32_t*)o->dns, o->dns_len, &error);
  write_dhcp_u32_array (buf, 44, (uint32_t*)o->wins, o->wins_len, &error);
  write_dhcp_u32_array (buf, 42, (uint32_t*)o->ntp, o->ntp_len, &error);
  write_dhcp_u32_array (buf, 45, (uint32_t*)o->nbdd, o->nbdd_len, &error);

  /* the MS DHCP server option 'Disable Netbios-over-TCP/IP
     is implemented as vendor option 001, value 002.
     A value of 001 means 'leave NBT alone' which is the default */
  if (o->disable_nbt)
  {
    if (!buf_safe (buf, 8))
      {
	msg (M_WARN, "build_dhcp_options_string: buffer overflow building DHCP options");
	return false;
      }
    buf_write_u8 (buf,  43);
    buf_write_u8 (buf,  6);  /* total length field */
    buf_write_u8 (buf,  0x001);
    buf_write_u8 (buf,  4);  /* length of the vendor specified field */
    buf_write_u32 (buf, 0x002);
  }
  return !error;
}

static void
fork_dhcp_action (struct tuntap *tt)
{
  if (tt->options.dhcp_pre_release || tt->options.dhcp_renew)
    {
      struct gc_arena gc = gc_new ();
      struct buffer cmd = alloc_buf_gc (256, &gc);
      const int verb = 3;
      const int pre_sleep = 1;
  
      buf_printf (&cmd, "openvpn --verb %d --tap-sleep %d", verb, pre_sleep);
      if (tt->options.dhcp_pre_release)
	buf_printf (&cmd, " --dhcp-pre-release");
      if (tt->options.dhcp_renew)
	buf_printf (&cmd, " --dhcp-renew");
      buf_printf (&cmd, " --dhcp-internal %u", (unsigned int)tt->adapter_index);

      fork_to_self (BSTR (&cmd));
      gc_free (&gc);
    }
}

void
fork_register_dns_action (struct tuntap *tt)
{
  if (tt && tt->options.register_dns)
    {
      struct gc_arena gc = gc_new ();
      struct buffer cmd = alloc_buf_gc (256, &gc);
      const int verb = 3;
 
      buf_printf (&cmd, "openvpn --verb %d --register-dns --rdns-internal", verb);
      fork_to_self (BSTR (&cmd));
      gc_free (&gc);
    }
}

static uint32_t
dhcp_masq_addr (const in_addr_t local, const in_addr_t netmask, const int offset)
{
  struct gc_arena gc = gc_new ();
  in_addr_t dsa; /* DHCP server addr */

  if (offset < 0)
    dsa = (local | (~netmask)) + offset;
  else
    dsa = (local & netmask) + offset;

  if (dsa == local)
    msg (M_FATAL, "ERROR: There is a clash between the --ifconfig local address and the internal DHCP server address -- both are set to %s -- please use the --ip-win32 dynamic option to choose a different free address from the --ifconfig subnet for the internal DHCP server", print_in_addr_t (dsa, 0, &gc));

  if ((local & netmask) != (dsa & netmask))
    msg (M_FATAL, "ERROR: --ip-win32 dynamic [offset] : offset is outside of --ifconfig subnet");

  gc_free (&gc);
  return htonl(dsa);
}

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
  struct gc_arena gc = gc_new ();
  char device_path[256];
  const char *device_guid = NULL;
  DWORD len;
  bool dhcp_masq = false;
  bool dhcp_masq_post = false;

  /*netcmd_semaphore_lock ();*/

  msg( M_INFO, "open_tun, tt->ipv6=%d", tt->ipv6 );

  if (tt->type == DEV_TYPE_NULL)
    {
      open_null (tt);
      gc_free (&gc);
      return;
    }
  else if (tt->type == DEV_TYPE_TAP || tt->type == DEV_TYPE_TUN)
    {
      ;
    }
  else
    {
      msg (M_FATAL|M_NOPREFIX, "Unknown virtual device type: '%s'", dev);
    }

  /*
   * Lookup the device name in the registry, using the --dev-node high level name.
   */
  {
    const struct tap_reg *tap_reg = get_tap_reg (&gc);
    const struct panel_reg *panel_reg = get_panel_reg (&gc);
    char actual_buffer[256];

    at_least_one_tap_win (tap_reg);

    if (dev_node)
      {
        /* Get the device GUID for the device specified with --dev-node. */
        device_guid = get_device_guid (dev_node, actual_buffer, sizeof (actual_buffer), tap_reg, panel_reg, &gc);

	if (!device_guid)
	  msg (M_FATAL, "TAP-Windows adapter '%s' not found", dev_node);

        /* Open Windows TAP-Windows adapter */
        openvpn_snprintf (device_path, sizeof(device_path), "%s%s%s",
   		          USERMODEDEVICEDIR,
		          device_guid,
		          TAP_WIN_SUFFIX);

        tt->hand = CreateFile (
			       device_path,
			       GENERIC_READ | GENERIC_WRITE,
			       0, /* was: FILE_SHARE_READ */
			       0,
			       OPEN_EXISTING,
			       FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
			       0
			       );

        if (tt->hand == INVALID_HANDLE_VALUE)
          msg (M_ERR, "CreateFile failed on TAP device: %s", device_path);
      }
    else 
      {
        int device_number = 0;

        /* Try opening all TAP devices until we find one available */
        while (true)
          {
            device_guid = get_unspecified_device_guid (device_number, 
						       actual_buffer, 
						       sizeof (actual_buffer),
						       tap_reg,
						       panel_reg,
						       &gc);

	    if (!device_guid)
	      msg (M_FATAL, "All TAP-Windows adapters on this system are currently in use.");

            /* Open Windows TAP-Windows adapter */
            openvpn_snprintf (device_path, sizeof(device_path), "%s%s%s",
       		  	      USERMODEDEVICEDIR,
			      device_guid,
			      TAP_WIN_SUFFIX);

            tt->hand = CreateFile (
			 	   device_path,
				   GENERIC_READ | GENERIC_WRITE,
				   0, /* was: FILE_SHARE_READ */
				   0,
				   OPEN_EXISTING,
				   FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
				   0
				   );

            if (tt->hand == INVALID_HANDLE_VALUE)
              msg (D_TUNTAP_INFO, "CreateFile failed on TAP device: %s", device_path);
            else
              break;
        
            device_number++;
          }
      }

    /* translate high-level device name into a device instance
       GUID using the registry */
    tt->actual_name = string_alloc (actual_buffer, NULL);
  }

  msg (M_INFO, "TAP-WIN32 device [%s] opened: %s", tt->actual_name, device_path);
  tt->adapter_index = get_adapter_index (device_guid);

  /* get driver version info */
  {
    ULONG info[3];
    CLEAR (info);
    if (DeviceIoControl (tt->hand, TAP_WIN_IOCTL_GET_VERSION,
			 &info, sizeof (info),
			 &info, sizeof (info), &len, NULL))
      {
	msg (D_TUNTAP_INFO, "TAP-Windows Driver Version %d.%d %s",
	     (int) info[0],
	     (int) info[1],
	     (info[2] ? "(DEBUG)" : ""));

      }
    if (!(info[0] == TAP_WIN_MIN_MAJOR && info[1] >= TAP_WIN_MIN_MINOR))
      msg (M_FATAL, "ERROR:  This version of " PACKAGE_NAME " requires a TAP-Windows driver that is at least version %d.%d -- If you recently upgraded your " PACKAGE_NAME " distribution, a reboot is probably required at this point to get Windows to see the new driver.",
	   TAP_WIN_MIN_MAJOR,
	   TAP_WIN_MIN_MINOR);

    /* usage of numeric constants is ugly, but this is really tied to
     * *this* version of the driver
     */
    if ( tt->ipv6 && tt->type == DEV_TYPE_TUN &&
         info[0] == 9 && info[1] < 8)
      {
	msg( M_INFO, "WARNING:  Tap-Win32 driver version %d.%d does not support IPv6 in TUN mode.  IPv6 will be disabled.  Upgrade to Tap-Win32 9.8 (2.2-beta3 release or later) or use TAP mode to get IPv6", (int) info[0], (int) info[1] );
	tt->ipv6 = false;
      }

    /* tap driver 9.8 (2.2.0 and 2.2.1 release) is buggy
     */
    if ( tt->type == DEV_TYPE_TUN &&
	 info[0] == 9 && info[1] == 8)
      {
	msg( M_FATAL, "ERROR:  Tap-Win32 driver version %d.%d is buggy regarding small IPv4 packets in TUN mode.  Upgrade to Tap-Win32 9.9 (2.2.2 release or later) or use TAP mode", (int) info[0], (int) info[1] );
      }
  }

  /* get driver MTU */
  {
    ULONG mtu;
    if (DeviceIoControl (tt->hand, TAP_WIN_IOCTL_GET_MTU,
			 &mtu, sizeof (mtu),
			 &mtu, sizeof (mtu), &len, NULL))
      {
	tt->post_open_mtu = (int) mtu;
	msg (D_MTU_INFO, "TAP-Windows MTU=%d", (int) mtu);
      }
  }

  /*
   * Preliminaries for setting TAP-Windows adapter TCP/IP
   * properties via --ip-win32 dynamic or --ip-win32 adaptive.
   */
  if (tt->did_ifconfig_setup)
    {
      if (tt->options.ip_win32_type == IPW32_SET_DHCP_MASQ)
	{
	  /*
	   * If adapter is set to non-DHCP, set to DHCP mode.
	   */
	  if (dhcp_status (tt->adapter_index) == DHCP_STATUS_DISABLED)
	    netsh_enable_dhcp (&tt->options, tt->actual_name);
	  dhcp_masq = true;
	  dhcp_masq_post = true;
	}
      else if (tt->options.ip_win32_type == IPW32_SET_ADAPTIVE)
	{
	  /*
	   * If adapter is set to non-DHCP, use netsh right away.
	   */
	  if (dhcp_status (tt->adapter_index) != DHCP_STATUS_ENABLED)
	    {
	      netsh_ifconfig (&tt->options,
			      tt->actual_name,
			      tt->local,
			      tt->adapter_netmask,
			      NI_TEST_FIRST|NI_IP_NETMASK|NI_OPTIONS);
	    }
	  else
	    {
	      dhcp_masq = true;
	    }
	}
    }

  /* set point-to-point mode if TUN device */

  if (tt->type == DEV_TYPE_TUN)
    {
      if (!tt->did_ifconfig_setup)
	{
	  msg (M_FATAL, "ERROR: --dev tun also requires --ifconfig");
	}

      if (tt->topology == TOP_SUBNET)
	{
	  in_addr_t ep[3];
	  BOOL status;

	  ep[0] = htonl (tt->local);
	  ep[1] = htonl (tt->local & tt->remote_netmask);
	  ep[2] = htonl (tt->remote_netmask);

	  status = DeviceIoControl (tt->hand, TAP_WIN_IOCTL_CONFIG_TUN,
				    ep, sizeof (ep),
				    ep, sizeof (ep), &len, NULL);

          msg (status ? M_INFO : M_FATAL, "Set TAP-Windows TUN subnet mode network/local/netmask = %s/%s/%s [%s]",
	       print_in_addr_t (ep[1], IA_NET_ORDER, &gc),
	       print_in_addr_t (ep[0], IA_NET_ORDER, &gc),
	       print_in_addr_t (ep[2], IA_NET_ORDER, &gc),
	       status ? "SUCCEEDED" : "FAILED");

	} else {

	  in_addr_t ep[2];
	  ep[0] = htonl (tt->local);
	  ep[1] = htonl (tt->remote_netmask);

	  if (!DeviceIoControl (tt->hand, TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT,
				ep, sizeof (ep),
				ep, sizeof (ep), &len, NULL))
	    msg (M_FATAL, "ERROR: The TAP-Windows driver rejected a DeviceIoControl call to set Point-to-Point mode, which is required for --dev tun");
	}
    }

  /* should we tell the TAP-Windows driver to masquerade as a DHCP server as a means
     of setting the adapter address? */
  if (dhcp_masq)
    {
      uint32_t ep[4];

      /* We will answer DHCP requests with a reply to set IP/subnet to these values */
      ep[0] = htonl (tt->local);
      ep[1] = htonl (tt->adapter_netmask);

      /* At what IP address should the DHCP server masquerade at? */
      if (tt->type == DEV_TYPE_TUN)
	{
	  if (tt->topology == TOP_SUBNET)
	    {
	      if (tt->options.dhcp_masq_custom_offset)
		ep[2] = dhcp_masq_addr (tt->local, tt->remote_netmask, tt->options.dhcp_masq_offset);
	      else
		ep[2] = dhcp_masq_addr (tt->local, tt->remote_netmask, -1);
	    }
	  else
	    ep[2] = htonl (tt->remote_netmask);
	}
      else
	{
	  ASSERT (tt->type == DEV_TYPE_TAP);
	  ep[2] = dhcp_masq_addr (tt->local, tt->adapter_netmask, tt->options.dhcp_masq_custom_offset ? tt->options.dhcp_masq_offset : 0);
	}

      /* lease time in seconds */
      ep[3] = (uint32_t) tt->options.dhcp_lease_time;

      ASSERT (ep[3] > 0);

#ifndef SIMULATE_DHCP_FAILED /* this code is disabled to simulate bad DHCP negotiation */
      if (!DeviceIoControl (tt->hand, TAP_WIN_IOCTL_CONFIG_DHCP_MASQ,
			    ep, sizeof (ep),
			    ep, sizeof (ep), &len, NULL))
	msg (M_FATAL, "ERROR: The TAP-Windows driver rejected a DeviceIoControl call to set TAP_WIN_IOCTL_CONFIG_DHCP_MASQ mode");

      msg (M_INFO, "Notified TAP-Windows driver to set a DHCP IP/netmask of %s/%s on interface %s [DHCP-serv: %s, lease-time: %d]",
	   print_in_addr_t (tt->local, 0, &gc),
	   print_in_addr_t (tt->adapter_netmask, 0, &gc),
	   device_guid,
	   print_in_addr_t (ep[2], IA_NET_ORDER, &gc),
	   ep[3]
	   );

      /* user-supplied DHCP options capability */
      if (tt->options.dhcp_options)
	{
	  struct buffer buf = alloc_buf (256);
	  if (build_dhcp_options_string (&buf, &tt->options))
	    {
	      msg (D_DHCP_OPT, "DHCP option string: %s", format_hex (BPTR (&buf), BLEN (&buf), 0, &gc));
	      if (!DeviceIoControl (tt->hand, TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT,
				    BPTR (&buf), BLEN (&buf),
				    BPTR (&buf), BLEN (&buf), &len, NULL))
		msg (M_FATAL, "ERROR: The TAP-Windows driver rejected a TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT DeviceIoControl call");
	    }
	  else
	    msg (M_WARN, "DHCP option string not set due to error");
	  free_buf (&buf);
	}
#endif
    }

  /* set driver media status to 'connected' */
  {
    ULONG status = TRUE;
    if (!DeviceIoControl (tt->hand, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
			  &status, sizeof (status),
			  &status, sizeof (status), &len, NULL))
      msg (M_WARN, "WARNING: The TAP-Windows driver rejected a TAP_WIN_IOCTL_SET_MEDIA_STATUS DeviceIoControl call.");
  }

  /* possible wait for adapter to come up */
  {
    int s = tt->options.tap_sleep;
    if (s > 0)
      {
	msg (M_INFO, "Sleeping for %d seconds...", s);
	openvpn_sleep (s);
      }
  }

  /* possibly use IP Helper API to set IP address on adapter */
  {
    const DWORD index = tt->adapter_index;
    
    /* flush arp cache */
    if (index != TUN_ADAPTER_INDEX_INVALID)
      {
	DWORD status;

	if ((status = FlushIpNetTable (index)) == NO_ERROR)
	  msg (M_INFO, "Successful ARP Flush on interface [%u] %s",
	       (unsigned int)index,
	       device_guid);
	else
	  msg (D_TUNTAP_INFO, "NOTE: FlushIpNetTable failed on interface [%u] %s (status=%u) : %s",
	       (unsigned int)index,
	       device_guid,
	       (unsigned int)status,
	       strerror_win32 (status, &gc));
      }

    /*
     * If the TAP-Windows driver is masquerading as a DHCP server
     * make sure the TCP/IP properties for the adapter are
     * set correctly.
     */
    if (dhcp_masq_post)
      {
	/* check dhcp enable status */
	if (dhcp_status (index) == DHCP_STATUS_DISABLED)
	  msg (M_WARN, "WARNING: You have selected '--ip-win32 dynamic', which will not work unless the TAP-Windows TCP/IP properties are set to 'Obtain an IP address automatically'");

	/* force an explicit DHCP lease renewal on TAP adapter? */
	if (tt->options.dhcp_pre_release)
	  dhcp_release (tt);
	if (tt->options.dhcp_renew)
	  dhcp_renew (tt);
      }
    else
      fork_dhcp_action (tt);

    if (tt->did_ifconfig_setup && tt->options.ip_win32_type == IPW32_SET_IPAPI)
      {
	DWORD status;
	const char *error_suffix = "I am having trouble using the Windows 'IP helper API' to automatically set the IP address -- consider using other --ip-win32 methods (not 'ipapi')";

	/* couldn't get adapter index */
	if (index == TUN_ADAPTER_INDEX_INVALID)
	  {
	    msg (M_FATAL, "ERROR: unable to get adapter index for interface %s -- %s",
		 device_guid,
		 error_suffix);
	  }

	/* check dhcp enable status */
	if (dhcp_status (index) == DHCP_STATUS_DISABLED)
	  msg (M_WARN, "NOTE: You have selected (explicitly or by default) '--ip-win32 ipapi', which has a better chance of working correctly if the TAP-Windows TCP/IP properties are set to 'Obtain an IP address automatically'");

	/* delete previously added IP addresses which were not
	   correctly deleted */
	delete_temp_addresses (index);

	/* add a new IP address */
	if ((status = AddIPAddress (htonl(tt->local),
				    htonl(tt->adapter_netmask),
				    index,
				    &tt->ipapi_context,
				    &tt->ipapi_instance)) == NO_ERROR)
	  msg (M_INFO, "Succeeded in adding a temporary IP/netmask of %s/%s to interface %s using the Win32 IP Helper API",
	       print_in_addr_t (tt->local, 0, &gc),
	       print_in_addr_t (tt->adapter_netmask, 0, &gc),
	       device_guid
	       );
	else
	  msg (M_FATAL, "ERROR: AddIPAddress %s/%s failed on interface %s, index=%d, status=%u (windows error: '%s') -- %s",
	       print_in_addr_t (tt->local, 0, &gc),
	       print_in_addr_t (tt->adapter_netmask, 0, &gc),
	       device_guid,
	       (int)index,
	       (unsigned int)status,
	       strerror_win32 (status, &gc),
	       error_suffix);
	tt->ipapi_context_defined = true;
      }
  }
  /*netcmd_semaphore_release ();*/
  gc_free (&gc);
}

const char *
tap_win_getinfo (const struct tuntap *tt, struct gc_arena *gc)
{
  if (tt && tt->hand != NULL)
    {
      struct buffer out = alloc_buf_gc (256, gc);
      DWORD len;
      if (DeviceIoControl (tt->hand, TAP_WIN_IOCTL_GET_INFO,
			   BSTR (&out), BCAP (&out),
			   BSTR (&out), BCAP (&out),
			   &len, NULL))
	{
	  return BSTR (&out);
	}
    }
  return NULL;
}

void
tun_show_debug (struct tuntap *tt)
{
  if (tt && tt->hand != NULL)
    {
      struct buffer out = alloc_buf (1024);
      DWORD len;
      while (DeviceIoControl (tt->hand, TAP_WIN_IOCTL_GET_LOG_LINE,
			      BSTR (&out), BCAP (&out),
			      BSTR (&out), BCAP (&out),
			      &len, NULL))
	{
	  msg (D_TAP_WIN_DEBUG, "TAP-Windows: %s", BSTR (&out));
	}
      free_buf (&out);
    }
}

void
close_tun (struct tuntap *tt)
{
  struct gc_arena gc = gc_new ();

  if (tt)
    {
      if ( tt->ipv6 && tt->did_ifconfig_ipv6_setup )
        {
	  const char *ifconfig_ipv6_local;
	  struct argv argv;
	  argv_init (&argv);

	  /* remove route pointing to interface */
	  delete_route_connected_v6_net(tt, NULL);

	  /* "store=active" is needed in Windows 8(.1) to delete the
	   * address we added (pointed out by Cedric Tabary).
	   */

	  /* netsh interface ipv6 delete address \"%s\" %s */
	  ifconfig_ipv6_local = print_in6_addr (tt->local_ipv6, 0,  &gc);
	  argv_printf (&argv,
		    "%s%sc interface ipv6 delete address %s %s store=active",
		     get_win_sys_path(),
		     NETSH_PATH_SUFFIX,
		     tt->actual_name,
		     ifconfig_ipv6_local );

	  netsh_command (&argv, 1);
          argv_reset (&argv);
	}
#if 1
      if (tt->ipapi_context_defined)
	{
	  DWORD status;
	  if ((status = DeleteIPAddress (tt->ipapi_context)) != NO_ERROR)
	    {
	      msg (M_WARN, "Warning: DeleteIPAddress[%u] failed on TAP-Windows adapter, status=%u : %s",
		   (unsigned int)tt->ipapi_context,
		   (unsigned int)status,
		   strerror_win32 (status, &gc));
	    }
	}
#endif

      if (tt->options.dhcp_release)
	dhcp_release (tt);

      if (tt->hand != NULL)
	{
	  dmsg (D_WIN32_IO_LOW, "Attempting CancelIO on TAP-Windows adapter");
	  if (!CancelIo (tt->hand))
	    msg (M_WARN | M_ERRNO, "Warning: CancelIO failed on TAP-Windows adapter");
	}

      dmsg (D_WIN32_IO_LOW, "Attempting close of overlapped read event on TAP-Windows adapter");
      overlapped_io_close (&tt->reads);

      dmsg (D_WIN32_IO_LOW, "Attempting close of overlapped write event on TAP-Windows adapter");
      overlapped_io_close (&tt->writes);

      if (tt->hand != NULL)
	{
	  dmsg (D_WIN32_IO_LOW, "Attempting CloseHandle on TAP-Windows adapter");
	  if (!CloseHandle (tt->hand))
	    msg (M_WARN | M_ERRNO, "Warning: CloseHandle failed on TAP-Windows adapter");
	}

      if (tt->actual_name)
	free (tt->actual_name);

      clear_tuntap (tt);
      free (tt);
    }
  gc_free (&gc);
}

/*
 * Convert --ip-win32 constants between index and ascii form.
 */

struct ipset_names {
  const char *short_form;
};

/* Indexed by IPW32_SET_x */
static const struct ipset_names ipset_names[] = {
  {"manual"},
  {"netsh"},
  {"ipapi"},
  {"dynamic"},
  {"adaptive"}
};

int
ascii2ipset (const char* name)
{
  int i;
  ASSERT (IPW32_SET_N == SIZE (ipset_names));
  for (i = 0; i < IPW32_SET_N; ++i)
    if (!strcmp (name, ipset_names[i].short_form))
      return i;
  return -1;
}

const char *
ipset2ascii (int index)
{
  ASSERT (IPW32_SET_N == SIZE (ipset_names));
  if (index < 0 || index >= IPW32_SET_N)
    return "[unknown --ip-win32 type]";
  else
    return ipset_names[index].short_form;
}

const char *
ipset2ascii_all (struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (256, gc);
  int i;

  ASSERT (IPW32_SET_N == SIZE (ipset_names));
  for (i = 0; i < IPW32_SET_N; ++i)
    {
      if (i)
	buf_printf(&out, " ");
      buf_printf(&out, "[%s]", ipset2ascii(i));
    }
  return BSTR (&out);
}

#else /* generic */

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
  open_tun_generic (dev, dev_type, dev_node, false, true, tt);
}

void
close_tun (struct tuntap* tt)
{
  if (tt)
    {
      close_tun_generic (tt);
      free (tt);
    }
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  return read (tt->fd, buf, len);
}

#endif
