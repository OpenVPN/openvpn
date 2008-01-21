/*
 * Support routine for configuring link layer address 
 */

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"
#include "error.h"
#include "misc.h"

int set_lladdr(const char *ifname, const char *lladdr,
		const struct env_set *es)
{
  char cmd[256];
  int r;

  if (!ifname || !lladdr)
    return -1;
  
#if defined(TARGET_LINUX)
#ifdef CONFIG_FEATURE_IPROUTE
  openvpn_snprintf (cmd, sizeof (cmd),
		    "%s link set addr %s dev %s",
		    iproute_path, lladdr, ifname);
#else
  openvpn_snprintf (cmd, sizeof (cmd),
		    IFCONFIG_PATH " %s hw ether %s",
		    ifname, lladdr);
#endif
#elif defined(TARGET_SOLARIS)
  openvpn_snprintf (cmd, sizeof (cmd),
		    IFCONFIG_PATH " %s ether %s",
		    ifname, lladdr);
#elif defined(TARGET_OPENBSD)
  openvpn_snprintf (cmd, sizeof (cmd),
		    IFCONFIG_PATH " %s lladdr %s",
		    ifname, lladdr);
#elif defined(TARGET_DARWIN)
  openvpn_snprintf (cmd, sizeof (cmd),
		    IFCONFIG_PATH " %s lladdr %s",
		    ifname, lladdr);
#elif defined(TARGET_FREEBSD)
  openvpn_snprintf (cmd, sizeof (cmd),
		    IFCONFIG_PATH " %s ether %s",
		    ifname, lladdr);
#else
      msg (M_WARN, "Sorry, but I don't know how to configure link layer addresses on this operating system.");
      return -1;
#endif

  r = system_check (cmd, es, M_WARN, "ERROR: Unable to set link layer address.");
  if (r)
    msg (M_INFO, "TUN/TAP link layer address set to %s", lladdr);
  return r;
}
