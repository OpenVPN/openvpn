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

/* packet filter functions */

#include "syshead.h"

#if defined(ENABLE_PF)

#include "init.h"

#include "memdbg.h"

static void
pf_destroy (struct pf_set *pfs)
{
  if (pfs)
    {
      if (pfs->cns.hash_table)
	hash_free (pfs->cns.hash_table);

      {
	struct pf_cn_elem *l = pfs->cns.list;
	while (l)
	  {
	    struct pf_cn_elem *next = l->next;
	    free (l->rule.cn);
	    free (l);
	    l = next;
	  }
      }
      {
	struct pf_subnet *l = pfs->sns.list;
	while (l)
	  {
	    struct pf_subnet *next = l->next;
	    free (l);
	    l = next;
	  }
      }
      free (pfs);
    }
}

static bool
add_client (const char *line, const char *fn, const int line_num, struct pf_cn_elem ***next, const bool exclude)
{
  struct pf_cn_elem *e;
  ALLOC_OBJ_CLEAR (e, struct pf_cn_elem);
  e->rule.exclude = exclude;
  e->rule.cn = string_alloc (line, NULL);
  **next = e;
  *next = &e->next;
  return true;
}

static bool
add_subnet (const char *line, const char *fn, const int line_num, struct pf_subnet ***next, const bool exclude)
{
  struct in_addr network;
  in_addr_t netmask = 0;
  int netbits = 32;
  char *div = strchr (line, '/');

  if (div)
    {
      *div++ = '\0';
      if (sscanf (div, "%d", &netbits) != 1)
	{
	  msg (D_PF, "PF: %s/%d: bad '/n' subnet specifier: '%s'", fn, line_num, div);
	  return false;
	}
      if (netbits < 0 || netbits > 32)
	{
	  msg (D_PF, "PF: %s/%d: bad '/n' subnet specifier: must be between 0 and 32: '%s'", fn, line_num, div);
	  return false;
	}
    }

  if (openvpn_inet_aton (line, &network) != OIA_IP)
    {
      msg (D_PF, "PF: %s/%d: bad network address: '%s'", fn, line_num, line);
      return false;
    }
  netmask = netbits_to_netmask (netbits);

  {
    struct pf_subnet *e;
    ALLOC_OBJ_CLEAR (e, struct pf_subnet);
    e->rule.exclude = exclude;
    e->rule.network = ntohl (network.s_addr);
    e->rule.netmask = netmask;
    **next = e;
    *next = &e->next;
    return true;
  }
}

static uint32_t
cn_hash_function (const void *key, uint32_t iv)
{
  return hash_func ((uint8_t *)key, strlen ((char *)key) + 1, iv);
}

static bool
cn_compare_function (const void *key1, const void *key2)
{
  return !strcmp((const char *)key1, (const char *)key2);
}

static bool
genhash (struct pf_cn_set *cns, const char *fn, const int n_clients)
{
  struct pf_cn_elem *e;
  bool status = true;
  int n_buckets = n_clients;

  if (n_buckets < 16)
    n_buckets = 16;
  cns->hash_table = hash_init (n_buckets, 0, cn_hash_function, cn_compare_function);
  for (e = cns->list; e != NULL; e = e->next)
    {
      if (!hash_add (cns->hash_table, e->rule.cn, &e->rule, false))
	{
	  msg (D_PF, "PF: %s: duplicate common name in [clients] section: '%s'", fn, e->rule.cn);
	  status = false;
	}
    }
  
  return status;
}

static struct pf_set *
pf_init (const char *fn)
{
# define MODE_UNDEF   0
# define MODE_CLIENTS 1
# define MODE_SUBNETS 2
  int mode = MODE_UNDEF;
  int line_num = 0;
  int n_clients = 0;
  int n_subnets = 0;
  int n_errors = 0;
  struct pf_set *pfs = NULL;
  char line[256];

  ALLOC_OBJ_CLEAR (pfs, struct pf_set);
  FILE *fp = fopen (fn, "r");
  if (fp)
    {
      struct pf_cn_elem **cl = &pfs->cns.list;
      struct pf_subnet **sl = &pfs->sns.list;

      while (fgets (line, sizeof (line), fp) != NULL)
	{
	  ++line_num;
	  rm_trailing_chars (line, "\r\n\t ");
	  if (line[0] == '\0' || line[0] == '#')
	    ;
	  else if (line[0] == '+' || line[0] == '-')
	    {
	      bool exclude = (line[0] == '-');

	      if (line[1] =='\0')
		{
		  msg (D_PF, "PF: %s/%d: no data after +/-: '%s'", fn, line_num, line);
		  ++n_errors;
		}
	      else if (mode == MODE_CLIENTS)
		{
		  if (add_client (&line[1], fn, line_num, &cl, exclude))
		    ++n_clients;
		  else
		    ++n_errors;
		}
	      else if (mode == MODE_SUBNETS)
		{
		  if (add_subnet (&line[1], fn, line_num, &sl, exclude))
		    ++n_subnets;
		  else
		    ++n_errors;
		}
	      else if (mode == MODE_UNDEF)
		;
	      else
		{
		  ASSERT (0);
		}
	    }
	  else if (line[0] == '[')
	    {
	      if (!strcasecmp (line, "[clients accept]"))
		{
		  mode = MODE_CLIENTS;
		  pfs->cns.default_allow = true;
		}
	      else if (!strcasecmp (line, "[clients drop]"))
		{
		  mode = MODE_CLIENTS;
		  pfs->cns.default_allow = false;
		}
	      else if (!strcasecmp (line, "[subnets accept]"))
		{
		  mode = MODE_SUBNETS;
		  pfs->sns.default_allow = true;
		}
	      else if (!strcasecmp (line, "[subnets drop]"))
		{
		  mode = MODE_SUBNETS;
		  pfs->sns.default_allow = false;
		}
	      else if (!strcasecmp (line, "[end]"))
		goto done;
	      else if (!strcasecmp (line, "[kill]"))
		goto kill;
	      else
		{
		  mode = MODE_UNDEF;
		  msg (D_PF, "PF: %s/%d unknown tag: '%s'", fn, line_num, line);
		  ++n_errors;
		}
	    }
	  else
	    {
	      msg (D_PF, "PF: %s/%d line must begin with '+', '-', or '[' : '%s'", fn, line_num, line);
	      ++n_errors;
	    }
	}
      ++n_errors;
      msg (D_PF, "PF: %s: missing [end]", fn);
    }
  else
    {
      msg (D_PF|M_ERRNO, "PF: %s: cannot open", fn);
      ++n_errors;
    }

 done:
  if (fp)
    {
      fclose (fp);
      if (!n_errors)
	{
	  if (!genhash (&pfs->cns, fn, n_clients))
	    ++n_errors;
	}
      if (n_errors)
	msg (D_PF, "PF: %s rejected due to %d error(s)", fn, n_errors);
    }
  if (n_errors)
    {
      pf_destroy (pfs);
      pfs = NULL;
    }
  return pfs;
  
 kill:
  if (fp)
    fclose (fp);
  pf_destroy (pfs);
  ALLOC_OBJ_CLEAR (pfs, struct pf_set);
  pfs->kill = true;
  return pfs;
}

#if PF_DEBUG >= 1

static const char *
drop_accept (const bool accept)
{
  return accept ? "ACCEPT" : "DROP"; 
}

#endif

#if PF_DEBUG >= 2

static void
pf_cn_test_print (const char *prefix,
		  const char *cn,
		  const bool allow,
		  const struct pf_cn *rule)
{
  if (rule)
    {
      msg (D_PF, "PF: %s %s %s rule=[%s %s]",
	   prefix, cn, drop_accept (allow),
	   rule->cn, drop_accept (!rule->exclude));
    }
  else
    {
      msg (D_PF, "PF: %s %s %s",
	   prefix, cn, drop_accept (allow));
    }
}

static void
pf_addr_test_print (const char *prefix,
		    const struct context *src,
		    const struct mroute_addr *dest,
		    const bool allow,
		    const struct ipv4_subnet *rule)
{
  struct gc_arena gc = gc_new ();
  if (rule)
    {
      msg (D_PF, "PF: %s %s %s %s rule=[%s/%s %s]",
	   prefix,
	   tls_common_name (src->c2.tls_multi, false),
	   mroute_addr_print (dest, &gc),
	   drop_accept (allow),
	   print_in_addr_t (rule->network, 0, &gc),
	   print_in_addr_t (rule->netmask, 0, &gc),
	   drop_accept (!rule->exclude));
    }
  else
    {
      msg (D_PF, "PF: %s %s %s %s",
	   prefix,
	   tls_common_name (src->c2.tls_multi, false),
	   mroute_addr_print (dest, &gc),
	   drop_accept (allow));
    }
  gc_free (&gc);
}

#endif

static inline struct pf_cn *
lookup_cn_rule (struct hash *h, const char *cn, const uint32_t cn_hash)
{
  struct hash_element *he = hash_lookup_fast (h, hash_bucket (h, cn_hash), cn, cn_hash);
  if (he)
    return (struct pf_cn *) he->value;
  else
    return NULL;
}

static inline bool
cn_test (struct pf_set *pfs, const struct tls_multi *tm)
{
  if (!pfs->kill)
    {
      const char *cn;
      uint32_t cn_hash;
      if (tls_common_name_hash (tm, &cn, &cn_hash))
	{
	  const struct pf_cn *rule = lookup_cn_rule (pfs->cns.hash_table, cn, cn_hash);
	  if (rule)
	    {
#if PF_DEBUG >= 2
	      pf_cn_test_print ("PF_CN_MATCH", cn, !rule->exclude, rule);
#endif
	      if (!rule->exclude)
		return true;
	      else
		return false;
	    }
	  else
	    {
#if PF_DEBUG >= 2
	      pf_cn_test_print ("PF_CN_DEFAULT", cn, pfs->cns.default_allow, NULL);
#endif
	      if (pfs->cns.default_allow)
		return true;
	      else
		return false;
	    }
	}
    }
#if PF_DEBUG >= 2
  pf_cn_test_print ("PF_CN_FAULT", tls_common_name (tm, false), false, NULL);
#endif
  return false;
}

bool
pf_c2c_test (const struct context *src, const struct context *dest)
{
  return  (!src->c2.pf.filename  || cn_test (src->c2.pf.pfs,  dest->c2.tls_multi))
       && (!dest->c2.pf.filename || cn_test (dest->c2.pf.pfs, src->c2.tls_multi));
}

bool
pf_addr_test (const struct context *src, const struct mroute_addr *dest)
{
  if (src->c2.pf.filename)
    {
      struct pf_set *pfs = src->c2.pf.pfs;
      if (pfs && !pfs->kill)
	{
	  const in_addr_t addr = in_addr_t_from_mroute_addr (dest);
	  const struct pf_subnet *se = pfs->sns.list;
	  while (se)
	    {
	      if ((addr & se->rule.netmask) == se->rule.network)
		{
#if PF_DEBUG >= 2
		  pf_addr_test_print ("PF_ADDR_MATCH", src, dest, !se->rule.exclude, &se->rule);
#endif
		  return !se->rule.exclude;
		}
	      se = se->next;
	    }
#if PF_DEBUG >= 2
	  pf_addr_test_print ("PF_ADDR_DEFAULT", src, dest, pfs->sns.default_allow, NULL);
#endif
	  return pfs->sns.default_allow;
	}
      else
	{
#if PF_DEBUG >= 2
	  pf_addr_test_print ("PF_ADDR_FAULT", src, dest, false, NULL);
#endif
	  return false;
	}
    }
  else
    {
      return true;
    }
}

void
pf_check_reload (struct context *c)
{
  const int slow_wakeup = 15;
  const int fast_wakeup = 1;
  const int wakeup_transition = 60;
  bool reloaded = false;

  if (c->c2.pf.filename && event_timeout_trigger (&c->c2.pf.reload, &c->c2.timeval, ETT_DEFAULT))
    {
      struct stat s;
      if (!stat (c->c2.pf.filename, &s))
	{
	  if (s.st_mtime > c->c2.pf.file_last_mod)
	    {
	      struct pf_set *pfs = pf_init (c->c2.pf.filename);
	      if (pfs)
		{
		  if (c->c2.pf.pfs)
		    pf_destroy (c->c2.pf.pfs);
		  c->c2.pf.pfs = pfs;
		  reloaded = true;
		  if (pf_kill_test (pfs))
		    {
		      c->sig->signal_received = SIGTERM;
		      c->sig->signal_text = "pf-kill";
		    }
		}
	      c->c2.pf.file_last_mod = s.st_mtime;
	    }
	}
      {
	int wakeup = slow_wakeup;
	if (!c->c2.pf.pfs && c->c2.pf.n_check_reload < wakeup_transition)
	  wakeup = fast_wakeup;
	event_timeout_init (&c->c2.pf.reload, wakeup, now);
	reset_coarse_timers (c);
	c->c2.pf.n_check_reload++;
      }
    }
#if PF_DEBUG >= 1
  if (reloaded)
    pf_context_print (&c->c2.pf, "pf_check_reload", M_INFO);
#endif
}

void
pf_init_context (struct context *c)
{
  struct gc_arena gc = gc_new ();
  if (plugin_defined (c->plugins, OPENVPN_PLUGIN_ENABLE_PF))
    {
      const char *pf_file = create_temp_filename (c->options.tmp_dir, "pf", &gc);
      delete_file (pf_file);
      setenv_str (c->c2.es, "pf_file", pf_file);

      if (plugin_call (c->plugins, OPENVPN_PLUGIN_ENABLE_PF, NULL, NULL, c->c2.es) == OPENVPN_PLUGIN_FUNC_SUCCESS)
	{
	  event_timeout_init (&c->c2.pf.reload, 1, now);
	  c->c2.pf.filename = string_alloc (pf_file, NULL);
#if PF_DEBUG >= 1
	  pf_context_print (&c->c2.pf, "pf_init_context", M_INFO);
#endif
	}
      else
	{
	  msg (M_WARN, "WARNING: OPENVPN_PLUGIN_ENABLE_PF disabled");
	}
    }
  gc_free (&gc);
}

void
pf_destroy_context (struct pf_context *pfc)
{
  if (pfc->filename)
    {
      delete_file (pfc->filename);
      free (pfc->filename);
    }
  if (pfc->pfs)
    pf_destroy (pfc->pfs);
}

#if PF_DEBUG >= 1

static void
pf_subnet_set_print (const struct pf_subnet_set *s, const int lev)
{
  struct gc_arena gc = gc_new ();
  if (s)
    {
      struct pf_subnet *e;

      msg (lev, "  ----- struct pf_subnet_set -----");
      msg (lev, "  default_allow=%s", drop_accept (s->default_allow));

      for (e = s->list; e != NULL; e = e->next)
	{
	  msg (lev, "   %s/%s %s",
	       print_in_addr_t (e->rule.network, 0, &gc),
	       print_in_addr_t (e->rule.netmask, 0, &gc),
	       drop_accept (!e->rule.exclude));
	}
    }
  gc_free (&gc);
}

static void
pf_cn_set_print (const struct pf_cn_set *s, const int lev)
{
  if (s)
    {
      struct hash_iterator hi;
      struct hash_element *he;

      msg (lev, "  ----- struct pf_cn_set -----");
      msg (lev, "  default_allow=%s", drop_accept (s->default_allow));

      if (s->hash_table)
	{
	  hash_iterator_init (s->hash_table, &hi, false);
	  while ((he = hash_iterator_next (&hi)))
	    {
	      struct pf_cn *e = (struct pf_cn *)he->value;
	      msg (lev, "   %s %s",
		   e->cn,
		   drop_accept (!e->exclude));
	    }

	  msg (lev, "  ----------");

	  {
	    struct pf_cn_elem *ce;
	    for (ce = s->list; ce != NULL; ce = ce->next)
	      {
		struct pf_cn *e = lookup_cn_rule (s->hash_table, ce->rule.cn, cn_hash_function (ce->rule.cn, 0));
		if (e)
		  {
		    msg (lev, "   %s %s",
			 e->cn,
			 drop_accept (!e->exclude));
		  }
		else
		  {
		    msg (lev, "   %s LOOKUP FAILED", ce->rule.cn);
		  }
	      }
	  }
	}
    }
}

static void
pf_set_print (const struct pf_set *pfs, const int lev)
{
  if (pfs)
    {
      msg (lev, " ----- struct pf_set -----");
      msg (lev, " kill=%d", pfs->kill);
      pf_subnet_set_print (&pfs->sns, lev);
      pf_cn_set_print (&pfs->cns, lev);
    }
}

void
pf_context_print (const struct pf_context *pfc, const char *prefix, const int lev)
{
  msg (lev, "----- %s : struct pf_context -----", prefix);
  if (pfc)
    {
      msg (lev, "filename='%s'", np(pfc->filename));
      msg (lev, "file_last_mod=%u", (unsigned int)pfc->file_last_mod);
      msg (lev, "n_check_reload=%u", pfc->n_check_reload);
      msg (lev, "reload=[%d,%u,%u]", pfc->reload.defined, pfc->reload.n, (unsigned int)pfc->reload.last);
      pf_set_print (pfc->pfs, lev);
    }
  msg (lev, "--------------------");
}

#endif

#endif
