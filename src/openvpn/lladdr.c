/*
 * Support routine for configuring link layer address 
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"
#include "error.h"
#include "misc.h"

int set_lladdr(const char *ifname, const char *lladdr,
		const struct env_set *es)
{
  struct argv argv = argv_new ();
  int r;

  if (!ifname || !lladdr)
    return -1;
  
#if defined(TARGET_LINUX)
#ifdef ENABLE_IPROUTE
  argv_printf (&argv,
		    "%s link set addr %s dev %s",
		    iproute_path, lladdr, ifname);
#else
  argv_printf (&argv,
		    "%s %s hw ether %s",
		    IFCONFIG_PATH,
		    ifname, lladdr);
#endif
#elif defined(TARGET_SOLARIS)
  argv_printf (&argv,
		    "%s %s ether %s",
		    IFCONFIG_PATH,
		    ifname, lladdr);
#elif defined(TARGET_OPENBSD)
  argv_printf (&argv,
		    "%s %s lladdr %s",
		    IFCONFIG_PATH,
		    ifname, lladdr);
#elif defined(TARGET_DARWIN)
  argv_printf (&argv,
		    "%s %s lladdr %s",
		    IFCONFIG_PATH,
		    ifname, lladdr);
#elif defined(TARGET_FREEBSD)
  argv_printf (&argv,
		    "%s %s ether %s",
		    IFCONFIG_PATH,
		    ifname, lladdr);
#else
      msg (M_WARN, "Sorry, but I don't know how to configure link layer addresses on this operating system.");
      return -1;
#endif

  argv_msg (M_INFO, &argv);
  r = openvpn_execve_check (&argv, es, M_WARN, "ERROR: Unable to set link layer address.");
  if (r)
    msg (M_INFO, "TUN/TAP link layer address set to %s", lladdr);

  argv_reset (&argv);
  return r;
}
