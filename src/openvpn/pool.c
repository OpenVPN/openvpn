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

#include "pool.h"
#include "buffer.h"
#include "error.h"
#include "socket.h"
#include "otime.h"

#include "memdbg.h"

#if P2MP

static void
ifconfig_pool_entry_free (struct ifconfig_pool_entry *ipe, bool hard)
{
  ipe->in_use = false;
  if (hard && ipe->common_name)
    {
      free (ipe->common_name);
      ipe->common_name = NULL;
    }
  if (hard)
    ipe->last_release = 0;
  else
    ipe->last_release = now;
}

static int
ifconfig_pool_find (struct ifconfig_pool *pool, const char *common_name)
{
  int i;
  time_t earliest_release = 0;
  int previous_usage = -1;
  int new_usage = -1;

  for (i = 0; i < pool->size; ++i)
    {
      struct ifconfig_pool_entry *ipe = &pool->list[i];
      if (!ipe->in_use)
	{
	  /*
	   * If duplicate_cn mode, take first available IP address
	   */
	  if (pool->duplicate_cn)
	    {
	      new_usage = i;
	      break;
	    }

	  /*
	   * Keep track of the unused IP address entry which
	   * was released earliest.
	   */
	  if ((new_usage == -1 || ipe->last_release < earliest_release) && !ipe->fixed)
	    {
	      earliest_release = ipe->last_release;
	      new_usage = i;
	    }

	  /*
	   * Keep track of a possible allocation to us
	   * from an earlier session.
	   */
	  if (previous_usage < 0
	      && common_name
	      && ipe->common_name
	      && !strcmp (common_name, ipe->common_name))
	    previous_usage = i;

	}
    }

  if (previous_usage >= 0)
    return previous_usage;

  if (new_usage >= 0)
    return new_usage;

  return -1;
}

/*
 * Verify start/end range
 */
bool
ifconfig_pool_verify_range (const int msglevel, const in_addr_t start, const in_addr_t end)
{
  struct gc_arena gc = gc_new ();
  bool ret = true;

  if (start > end)
    {
      msg (msglevel, "--ifconfig-pool start IP [%s] is greater than end IP [%s]",
	   print_in_addr_t (start, 0, &gc),
	   print_in_addr_t (end, 0, &gc));
      ret = false;
    }
  if (end - start >= IFCONFIG_POOL_MAX)
    {
      msg (msglevel, "--ifconfig-pool address range is too large [%s -> %s].  Current maximum is %d addresses, as defined by IFCONFIG_POOL_MAX variable.",
	   print_in_addr_t (start, 0, &gc),
	   print_in_addr_t (end, 0, &gc),
	   IFCONFIG_POOL_MAX);
      ret = false;
    }
  gc_free (&gc);
  return ret;
}

struct ifconfig_pool *
ifconfig_pool_init (int type, in_addr_t start, in_addr_t end, 
		    const bool duplicate_cn,
		    const bool ipv6_pool, const struct in6_addr ipv6_base, 
		    const int ipv6_netbits )
{
  struct gc_arena gc = gc_new ();
  struct ifconfig_pool *pool = NULL;

  ASSERT (start <= end && end - start < IFCONFIG_POOL_MAX);
  ALLOC_OBJ_CLEAR (pool, struct ifconfig_pool);

  pool->type = type;
  pool->duplicate_cn = duplicate_cn;

  switch (type)
    {
    case IFCONFIG_POOL_30NET:
      pool->base = start & ~3;
      pool->size = (((end | 3) + 1) - pool->base) >> 2;
      break;
    case IFCONFIG_POOL_INDIV:
      pool->base = start;
      pool->size = end - start + 1;
      break;
    default:
      ASSERT (0);
    }

  /* IPv6 pools are always "INDIV" type */
  pool->ipv6 = ipv6_pool;

  if ( pool->ipv6 )
    {
      pool->base_ipv6 = ipv6_base;
      pool->size_ipv6 = ipv6_netbits>96? ( 1<<(128-ipv6_netbits) ) 
				       : IFCONFIG_POOL_MAX;

      msg( D_IFCONFIG_POOL, "IFCONFIG POOL IPv6: (IPv4) size=%d, size_ipv6=%d, netbits=%d, base_ipv6=%s",
			    pool->size, pool->size_ipv6, ipv6_netbits,
			    print_in6_addr( pool->base_ipv6, 0, &gc ));

      /* the current code is very simple and assumes that the IPv6
       * pool is at least as big as the IPv4 pool, and we don't need
       * to do separate math etc. for IPv6
       */
      ASSERT( pool->size < pool->size_ipv6 );
    }

  ALLOC_ARRAY_CLEAR (pool->list, struct ifconfig_pool_entry, pool->size);

  msg (D_IFCONFIG_POOL, "IFCONFIG POOL: base=%s size=%d, ipv6=%d",
       print_in_addr_t (pool->base, 0, &gc),
       pool->size, pool->ipv6 );

  gc_free (&gc);
  return pool;
}

void
ifconfig_pool_free (struct ifconfig_pool *pool)
{
  if (pool)
    {
      int i;
      for (i = 0; i < pool->size; ++i)
	ifconfig_pool_entry_free (&pool->list[i], true);
      free (pool->list);
      free (pool);
    }
}

ifconfig_pool_handle
ifconfig_pool_acquire (struct ifconfig_pool *pool, in_addr_t *local, in_addr_t *remote, struct in6_addr *remote_ipv6, const char *common_name)
{
  int i;

  i = ifconfig_pool_find (pool, common_name);
  if (i >= 0)
    {
      struct ifconfig_pool_entry *ipe = &pool->list[i];
      ASSERT (!ipe->in_use);
      ifconfig_pool_entry_free (ipe, true);
      ipe->in_use = true;
      if (common_name)
	ipe->common_name = string_alloc (common_name, NULL);

      switch (pool->type)
	{
	case IFCONFIG_POOL_30NET:
	  {
	    in_addr_t b = pool->base + (i << 2);
	    *local = b + 1;
	    *remote = b + 2;
	    break;
	  }
	case IFCONFIG_POOL_INDIV:
	  {
	    in_addr_t b = pool->base + i;
	    *local = 0;
	    *remote = b;
	    break;
	  }
	default:
	  ASSERT (0);
	}

      /* IPv6 pools are always INDIV (--linear) */
      if ( pool->ipv6 && remote_ipv6 )
	{
	  *remote_ipv6 = add_in6_addr( pool->base_ipv6, i );
	}
    }
  return i;
}

bool
ifconfig_pool_release (struct ifconfig_pool* pool, ifconfig_pool_handle hand, const bool hard)
{
  bool ret = false;
  if (pool && hand >= 0 && hand < pool->size)
    {
      ifconfig_pool_entry_free (&pool->list[hand], hard);
      ret = true;
    }
  return ret;
}

/*
 * private access functions
 */

static ifconfig_pool_handle
ifconfig_pool_ip_base_to_handle (const struct ifconfig_pool* pool, const in_addr_t addr)
{
  ifconfig_pool_handle ret = -1;

  switch (pool->type)
    {
    case IFCONFIG_POOL_30NET:
      {
	ret = (addr - pool->base) >> 2;
	break;
      }
    case IFCONFIG_POOL_INDIV:
      {
	ret = (addr - pool->base);
	break;
      }
    default:
      ASSERT (0);
    }

  if (ret < 0 || ret >= pool->size)
    ret = -1;

  return ret;
}

static in_addr_t
ifconfig_pool_handle_to_ip_base (const struct ifconfig_pool* pool, ifconfig_pool_handle hand)
{
  in_addr_t ret = 0;

  if (hand >= 0 && hand < pool->size)
    {
      switch (pool->type)
	{
	case IFCONFIG_POOL_30NET:
	  {
	    ret = pool->base + (hand << 2);;
	    break;
	  }
	case IFCONFIG_POOL_INDIV:
	  {
	    ret = pool->base + hand;
	    break;
	  }
	default:
	  ASSERT (0);
	}
    }

  return ret;
}

static struct in6_addr
ifconfig_pool_handle_to_ipv6_base (const struct ifconfig_pool* pool, ifconfig_pool_handle hand)
{
  struct in6_addr ret = in6addr_any;

  /* IPv6 pools are always INDIV (--linear) */
  if (hand >= 0 && hand < pool->size_ipv6 )
    {
      ret = add_in6_addr( pool->base_ipv6, hand );
    }
  return ret;
}

static void
ifconfig_pool_set (struct ifconfig_pool* pool, const char *cn, const in_addr_t addr, const bool fixed)
{
  ifconfig_pool_handle h = ifconfig_pool_ip_base_to_handle (pool, addr);
  if (h >= 0)
    {
      struct ifconfig_pool_entry *e = &pool->list[h];
      ifconfig_pool_entry_free (e, true);
      e->in_use = false;
      e->common_name = string_alloc (cn, NULL);
      e->last_release = now;
      e->fixed = fixed;
    }
}

static void
ifconfig_pool_list (const struct ifconfig_pool* pool, struct status_output *out)
{
  if (pool && out)
    {
      struct gc_arena gc = gc_new ();
      int i;

      for (i = 0; i < pool->size; ++i)
	{
	  const struct ifconfig_pool_entry *e = &pool->list[i];
	  if (e->common_name)
	    {
	      const in_addr_t ip = ifconfig_pool_handle_to_ip_base (pool, i);
	      if ( pool->ipv6 )
		{
		  struct in6_addr ip6 = ifconfig_pool_handle_to_ipv6_base (pool, i);
		  status_printf (out, "%s,%s,%s",
				 e->common_name,
				 print_in_addr_t (ip, 0, &gc),
				 print_in6_addr (ip6, 0, &gc));
		}
	      else
		{
		  status_printf (out, "%s,%s",
				 e->common_name,
				 print_in_addr_t (ip, 0, &gc));
		}
	    }
	}
      gc_free (&gc);
    }
}

static void
ifconfig_pool_msg (const struct ifconfig_pool* pool, int msglevel)
{
  struct status_output *so = status_open (NULL, 0, msglevel, NULL, 0);
  ASSERT (so);
  status_printf (so, "IFCONFIG POOL LIST");
  ifconfig_pool_list (pool, so);
  status_close (so);
}

/*
 * Deal with reading/writing the ifconfig pool database to a file
 */

struct ifconfig_pool_persist *
ifconfig_pool_persist_init (const char *filename, int refresh_freq)
{
  struct ifconfig_pool_persist *ret;

  ASSERT (filename);

  ALLOC_OBJ_CLEAR (ret, struct ifconfig_pool_persist);
  if (refresh_freq > 0)
    {
      ret->fixed = false;
      ret->file = status_open (filename, refresh_freq, -1, NULL, STATUS_OUTPUT_READ|STATUS_OUTPUT_WRITE);
    }
  else
    {
      ret->fixed = true;
      ret->file = status_open (filename, 0, -1, NULL, STATUS_OUTPUT_READ);
    }
  return ret;
}

void
ifconfig_pool_persist_close (struct ifconfig_pool_persist *persist)
{
  if (persist)
    {
      if (persist->file)
	status_close (persist->file);
      free (persist);
    }
}

bool
ifconfig_pool_write_trigger (struct ifconfig_pool_persist *persist)
{
  if (persist->file)
    return status_trigger (persist->file);
  else
    return false;
}

void
ifconfig_pool_read (struct ifconfig_pool_persist *persist, struct ifconfig_pool *pool)
{
  const int buf_size = 128;

  update_time ();
  if (persist && persist->file && pool)
    {
      struct gc_arena gc = gc_new ();
      struct buffer in = alloc_buf_gc (256, &gc);
      char *cn_buf;
      char *ip_buf;
      int line = 0;

      ALLOC_ARRAY_CLEAR_GC (cn_buf, char, buf_size, &gc);
      ALLOC_ARRAY_CLEAR_GC (ip_buf, char, buf_size, &gc);

      while (true)
	{
	  ASSERT (buf_init (&in, 0));
	  if (!status_read (persist->file, &in))
	    break;
	  ++line;
	  if (BLEN (&in))
	    {
	      int c = *BSTR(&in);
	      if (c == '#' || c == ';')
		continue;
	      msg( M_INFO, "ifconfig_pool_read(), in='%s', TODO: IPv6",
				BSTR(&in) );

	      if (buf_parse (&in, ',', cn_buf, buf_size)
		  && buf_parse (&in, ',', ip_buf, buf_size))
		{
		  bool succeeded;
		  const in_addr_t addr = getaddr (GETADDR_HOST_ORDER, ip_buf, 0, &succeeded, NULL);
		  if (succeeded)
		    {
		      msg( M_INFO, "succeeded -> ifconfig_pool_set()");
		      ifconfig_pool_set (pool, cn_buf, addr, persist->fixed);
		    }
		}
	    }
	}

      ifconfig_pool_msg (pool, D_IFCONFIG_POOL);
  
      gc_free (&gc);
    }
}

void
ifconfig_pool_write (struct ifconfig_pool_persist *persist, const struct ifconfig_pool *pool)
{
  if (persist && persist->file && (status_rw_flags (persist->file) & STATUS_OUTPUT_WRITE) && pool)
    {
      status_reset (persist->file);
      ifconfig_pool_list (pool, persist->file);
      status_flush (persist->file);
    }
}

/*
 * TESTING ONLY
 */

#ifdef IFCONFIG_POOL_TEST

#define DUP_CN

void
ifconfig_pool_test (in_addr_t start, in_addr_t end)
{
  struct gc_arena gc = gc_new ();
  struct ifconfig_pool *p = ifconfig_pool_init (IFCONFIG_POOL_30NET, start, end); 
  /*struct ifconfig_pool *p = ifconfig_pool_init (IFCONFIG_POOL_INDIV, start, end);*/
  ifconfig_pool_handle array[256];
  int i;

  CLEAR (array);

  msg (M_INFO | M_NOPREFIX, "************ 1");
  for (i = 0; i < (int) SIZE (array); ++i)
    {
      char *cn;
      ifconfig_pool_handle h;
      in_addr_t local, remote;
      char buf[256];
      openvpn_snprintf (buf, sizeof(buf), "common-name-%d", i);
#ifdef DUP_CN
      cn = NULL;
#else
      cn = buf;
#endif
      h = ifconfig_pool_acquire (p, &local, &remote, NULL, cn);
      if (h < 0)
	break;
      msg (M_INFO | M_NOPREFIX, "IFCONFIG_POOL TEST pass 1: l=%s r=%s cn=%s",
	   print_in_addr_t (local, 0, &gc),
	   print_in_addr_t (remote, 0, &gc),
	   cn);
      array[i] = h;
      
    }

  msg (M_INFO | M_NOPREFIX, "************* 2");
  for (i = (int) SIZE (array) / 16; i < (int) SIZE (array) / 8; ++i)
    {
      msg (M_INFO, "Attempt to release %d cn=%s", array[i], p->list[i].common_name);
      if (!ifconfig_pool_release (p, array[i]))
	break;
      msg (M_INFO, "Succeeded");
    }

  CLEAR (array);

  msg (M_INFO | M_NOPREFIX, "**************** 3");
  for (i = 0; i < (int) SIZE (array); ++i)
    {
      char *cn;
      ifconfig_pool_handle h;
      in_addr_t local, remote;
      char buf[256];
      snprintf (buf, sizeof(buf), "common-name-%d", i+24); 
#ifdef DUP_CN
      cn = NULL;
#else
      cn = buf;
#endif
      h = ifconfig_pool_acquire (p, &local, &remote, NULL, cn);
      if (h < 0)
	break;
      msg (M_INFO | M_NOPREFIX, "IFCONFIG_POOL TEST pass 3: l=%s r=%s cn=%s",
	   print_in_addr_t (local, 0, &gc),
	   print_in_addr_t (remote, 0, &gc),
	   cn);
      array[i] = h;
      
    }

  ifconfig_pool_free (p);
  gc_free (&gc);
}

#endif

#endif
