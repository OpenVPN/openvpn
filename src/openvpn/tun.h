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

#ifndef TUN_H
#define TUN_H

#ifdef WIN32
#include <winioctl.h>
#include <tap-windows.h>
#endif

#include "buffer.h"
#include "error.h"
#include "mtu.h"
#include "win32.h"
#include "event.h"
#include "proto.h"
#include "misc.h"

#ifdef WIN32

#define TUN_ADAPTER_INDEX_INVALID ((DWORD)-1)

/* time constants for --ip-win32 adaptive */
#define IPW32_SET_ADAPTIVE_DELAY_WINDOW 300
#define IPW32_SET_ADAPTIVE_TRY_NETSH    20

struct tuntap_options {
  /* --ip-win32 options */
  bool ip_win32_defined;

# define IPW32_SET_MANUAL       0  /* "--ip-win32 manual" */
# define IPW32_SET_NETSH        1  /* "--ip-win32 netsh" */
# define IPW32_SET_IPAPI        2  /* "--ip-win32 ipapi" */
# define IPW32_SET_DHCP_MASQ    3  /* "--ip-win32 dynamic" */
# define IPW32_SET_ADAPTIVE     4  /* "--ip-win32 adaptive" */
# define IPW32_SET_N            5
  int ip_win32_type;

  /* --ip-win32 dynamic options */
  bool dhcp_masq_custom_offset;
  int dhcp_masq_offset;
  int dhcp_lease_time;

  /* --tap-sleep option */
  int tap_sleep;

  /* --dhcp-option options */

  bool dhcp_options;

  const char *domain;        /* DOMAIN (15) */

  const char *netbios_scope; /* NBS (47) */

  int netbios_node_type;     /* NBT 1,2,4,8 (46) */

#define N_DHCP_ADDR 4        /* Max # of addresses allowed for
			        DNS, WINS, etc. */

  /* DNS (6) */
  in_addr_t dns[N_DHCP_ADDR];
  int dns_len;

  /* WINS (44) */
  in_addr_t wins[N_DHCP_ADDR];
  int wins_len;

  /* NTP (42) */
  in_addr_t ntp[N_DHCP_ADDR];
  int ntp_len;

  /* NBDD (45) */
  in_addr_t nbdd[N_DHCP_ADDR];
  int nbdd_len;

  /* DISABLE_NBT (43, Vendor option 001) */
  bool disable_nbt;

  bool dhcp_renew;
  bool dhcp_pre_release;
  bool dhcp_release;

  bool register_dns;
};

#elif TARGET_LINUX

struct tuntap_options {
  int txqueuelen;
};

#else

struct tuntap_options {
  int dummy; /* not used */
};

#endif

/*
 * Define a TUN/TAP dev.
 */

struct tuntap
{
# define TUNNEL_TYPE(tt) ((tt) ? ((tt)->type) : DEV_TYPE_UNDEF)
  int type; /* DEV_TYPE_x as defined in proto.h */

# define TUNNEL_TOPOLOGY(tt) ((tt) ? ((tt)->topology) : TOP_UNDEF)
  int topology; /* one of the TOP_x values */

  bool did_ifconfig_setup;
  bool did_ifconfig_ipv6_setup;
  bool did_ifconfig;

  bool ipv6;

  bool persistent_if;		/* if existed before, keep on program end */

  struct tuntap_options options; /* options set on command line */

  char *actual_name; /* actual name of TUN/TAP dev, usually including unit number */

  /* number of TX buffers */
  int txqueuelen;

  /* ifconfig parameters */
  in_addr_t local;
  in_addr_t remote_netmask;
  in_addr_t broadcast;

  struct in6_addr local_ipv6;
  struct in6_addr remote_ipv6;
  int netbits_ipv6;

#ifdef WIN32
  HANDLE hand;
  struct overlapped_io reads;
  struct overlapped_io writes;
  struct rw_handle rw_handle;

  /* used for setting interface address via IP Helper API
     or DHCP masquerade */
  bool ipapi_context_defined;
  ULONG ipapi_context;
  ULONG ipapi_instance;
  in_addr_t adapter_netmask;

  /* Windows adapter index for TAP-Windows adapter,
     ~0 if undefined */
  DWORD adapter_index;

  int standby_iter;
#else
  int fd;   /* file descriptor for TUN/TAP dev */
#endif

#ifdef TARGET_SOLARIS
  int ip_fd;
#endif

#ifdef HAVE_NET_IF_UTUN_H
  bool is_utun;
#endif
  /* used for printing status info only */
  unsigned int rwflags_debug;

  /* Some TUN/TAP drivers like to be ioctled for mtu
     after open */
  int post_open_mtu;
};

static inline bool
tuntap_defined (const struct tuntap *tt)
{
#ifdef WIN32
  return tt && tt->hand != NULL;
#else
  return tt && tt->fd >= 0;
#endif
}

/*
 * Function prototypes
 */

void open_tun (const char *dev, const char *dev_type, const char *dev_node,
	       struct tuntap *tt);

void close_tun (struct tuntap *tt);

int write_tun (struct tuntap* tt, uint8_t *buf, int len);

int read_tun (struct tuntap* tt, uint8_t *buf, int len);

void tuncfg (const char *dev, const char *dev_type, const char *dev_node,
	     int persist_mode, const char *username,
	     const char *groupname, const struct tuntap_options *options);

const char *guess_tuntap_dev (const char *dev,
			      const char *dev_type,
			      const char *dev_node,
			      struct gc_arena *gc);

struct tuntap *init_tun (const char *dev,       /* --dev option */
			 const char *dev_type,  /* --dev-type option */
			 int topology,          /* one of the TOP_x values */
			 const char *ifconfig_local_parm,          /* --ifconfig parm 1 */
			 const char *ifconfig_remote_netmask_parm, /* --ifconfig parm 2 */
			 const char *ifconfig_ipv6_local_parm,     /* --ifconfig parm 1 / IPv6 */
			 int ifconfig_ipv6_netbits_parm,           /* --ifconfig parm 1 / bits */
			 const char *ifconfig_ipv6_remote_parm,    /* --ifconfig parm 2 / IPv6 */
			 in_addr_t local_public,
			 in_addr_t remote_public,
			 const bool strict_warn,
			 struct env_set *es);

void init_tun_post (struct tuntap *tt,
		    const struct frame *frame,
		    const struct tuntap_options *options);

void do_ifconfig_setenv (const struct tuntap *tt,
		  struct env_set *es);

void do_ifconfig (struct tuntap *tt,
		  const char *actual,    /* actual device name */
		  int tun_mtu,
		  const struct env_set *es);

bool is_dev_type (const char *dev, const char *dev_type, const char *match_type);
int dev_type_enum (const char *dev, const char *dev_type);
const char *dev_type_string (const char *dev, const char *dev_type);

const char *ifconfig_options_string (const struct tuntap* tt, bool remote, bool disable, struct gc_arena *gc);

bool is_tun_p2p (const struct tuntap *tt);

void check_subnet_conflict (const in_addr_t ip,
			    const in_addr_t netmask,
			    const char *prefix);

void warn_on_use_of_common_subnets (void);

/*
 * Inline functions
 */

static inline void
tun_adjust_frame_parameters (struct frame* frame, int size)
{
  frame_add_to_extra_tun (frame, size);
}

/*
 * Should ifconfig be called before or after
 * tun dev open?
 */

#define IFCONFIG_BEFORE_TUN_OPEN 0
#define IFCONFIG_AFTER_TUN_OPEN  1

#define IFCONFIG_DEFAULT         IFCONFIG_AFTER_TUN_OPEN

static inline int
ifconfig_order(void)
{
#if defined(TARGET_LINUX)
  return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_SOLARIS)
  return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_OPENBSD)
  return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_DARWIN)
  return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_NETBSD)
  return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(WIN32)
  return IFCONFIG_BEFORE_TUN_OPEN;
#else
  return IFCONFIG_DEFAULT;
#endif
}

#ifdef WIN32

#define TUN_PASS_BUFFER

struct tap_reg
{
  const char *guid;
  struct tap_reg *next;
};

struct panel_reg
{
  const char *name;
  const char *guid;
  struct panel_reg *next;
};

int ascii2ipset (const char* name);
const char *ipset2ascii (int index);
const char *ipset2ascii_all (struct gc_arena *gc);

void verify_255_255_255_252 (in_addr_t local, in_addr_t remote);

const IP_ADAPTER_INFO *get_adapter_info_list (struct gc_arena *gc);
const IP_ADAPTER_INFO *get_tun_adapter (const struct tuntap *tt, const IP_ADAPTER_INFO *list);

const IP_ADAPTER_INFO *get_adapter_info (DWORD index, struct gc_arena *gc);
const IP_PER_ADAPTER_INFO *get_per_adapter_info (const DWORD index, struct gc_arena *gc);
const IP_ADAPTER_INFO *get_adapter (const IP_ADAPTER_INFO *ai, DWORD index);

bool is_adapter_up (const struct tuntap *tt, const IP_ADAPTER_INFO *list);
bool is_ip_in_adapter_subnet (const IP_ADAPTER_INFO *ai, const in_addr_t ip, in_addr_t *highest_netmask);

DWORD adapter_index_of_ip (const IP_ADAPTER_INFO *list,
			   const in_addr_t ip,
			   int *count,
			   in_addr_t *netmask);

void show_tap_win_adapters (int msglev, int warnlev);
void show_adapters (int msglev);

void tap_allow_nonadmin_access (const char *dev_node);

void show_valid_win32_tun_subnets (void);
const char *tap_win_getinfo (const struct tuntap *tt, struct gc_arena *gc);
void tun_show_debug (struct tuntap *tt);

bool dhcp_release_by_adapter_index(const DWORD adapter_index);
bool dhcp_renew_by_adapter_index (const DWORD adapter_index);

void fork_register_dns_action (struct tuntap *tt);
void ipconfig_register_dns (const struct env_set *es);

void tun_standby_init (struct tuntap *tt);
bool tun_standby (struct tuntap *tt);

int tun_read_queue (struct tuntap *tt, int maxsize);
int tun_write_queue (struct tuntap *tt, struct buffer *buf);
int tun_finalize (HANDLE h, struct overlapped_io *io, struct buffer *buf);

static inline bool
tuntap_stop (int status)
{
  /*
   * This corresponds to the STATUS_NO_SUCH_DEVICE
   * error in tapdrvr.c.
   */
  if (status < 0)
    {
      return openvpn_errno () == ERROR_FILE_NOT_FOUND;
    }
  return false;
}

static inline bool
tuntap_abort(int status)
{
  /*
   * Typically generated when driver is halted.
   */
  if (status < 0)
    {
      return openvpn_errno() == ERROR_OPERATION_ABORTED;
    }
  return false;
}

static inline int
tun_write_win32 (struct tuntap *tt, struct buffer *buf)
{
  int err = 0;
  int status = 0;
  if (overlapped_io_active (&tt->writes))
    {
      status = tun_finalize (tt->hand, &tt->writes, NULL);
      if (status < 0)
	err = GetLastError ();
    }
  tun_write_queue (tt, buf);
  if (status < 0)
    {
      SetLastError (err);
      return status;
    }
  else
    return BLEN (buf);
}

static inline int
read_tun_buffered (struct tuntap *tt, struct buffer *buf, int maxsize)
{
  return tun_finalize (tt->hand, &tt->reads, buf);
}

static inline int
write_tun_buffered (struct tuntap *tt, struct buffer *buf)
{
  return tun_write_win32 (tt, buf);
}

#else

static inline bool
tuntap_stop (int status)
{
  return false;
}

static inline bool
tuntap_abort(int status)
{
  return false;
}

static inline void
tun_standby_init (struct tuntap *tt)
{
}

static inline bool
tun_standby (struct tuntap *tt)
{
  return true;
}

#endif

/*
 * TUN/TAP I/O wait functions
 */

static inline event_t
tun_event_handle (const struct tuntap *tt)
{
#ifdef WIN32
  return &tt->rw_handle;
#else
  return tt->fd;
#endif
}

static inline unsigned int
tun_set (struct tuntap *tt,
	 struct event_set *es,
	 unsigned int rwflags,
	 void *arg,
	 unsigned int *persistent)
{
  if (tuntap_defined (tt))
    {
      /* if persistent is defined, call event_ctl only if rwflags has changed since last call */
      if (!persistent || *persistent != rwflags)
	{
	  event_ctl (es, tun_event_handle (tt), rwflags, arg);
	  if (persistent)
	    *persistent = rwflags;
	}
#ifdef WIN32
      if (rwflags & EVENT_READ)
	tun_read_queue (tt, 0);
#endif
      tt->rwflags_debug = rwflags;
    }
  return rwflags;
}

const char *tun_stat (const struct tuntap *tt, unsigned int rwflags, struct gc_arena *gc);

#endif /* TUN_H */
