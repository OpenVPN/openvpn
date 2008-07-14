/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2008 Telethra, Inc. <sales@openvpn.net>
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

#include "syshead.h"

#include "push.h"
#include "options.h"
#include "ssl.h"
#include "manage.h"

#include "memdbg.h"

#if P2MP

/*
 * Auth username/password
 *
 * Client received an authentication failed message from server.
 * Runs on client.
 */
void
receive_auth_failed (struct context *c, const struct buffer *buffer)
{
  msg (M_VERB0, "AUTH: Received AUTH_FAILED control message");
  if (c->options.pull)
    {
      switch (auth_retry_get ())
	{
	case AR_NONE:
	  c->sig->signal_received = SIGTERM; /* SOFT-SIGTERM -- Auth failure error */
	  break;
	case AR_INTERACT:
	  ssl_purge_auth ();
	case AR_NOINTERACT:
	  c->sig->signal_received = SIGUSR1; /* SOFT-SIGUSR1 -- Auth failure error */
	  break;
	default:
	  ASSERT (0);
	}
      c->sig->signal_text = "auth-failure";
#ifdef ENABLE_MANAGEMENT
      if (management)
	management_auth_failure (management, UP_TYPE_AUTH);
#endif
    }
}

#if P2MP_SERVER
/*
 * Send auth failed message from server to client.
 */
void
send_auth_failed (struct context *c)
{
  schedule_exit (c, c->options.scheduled_exit_interval);
  send_control_channel_string (c, "AUTH_FAILED", D_PUSH);
}
#endif

/*
 * Push/Pull
 */

void
incoming_push_message (struct context *c, const struct buffer *buffer)
{
  struct gc_arena gc = gc_new ();
  unsigned int option_types_found = 0;
  int status;

  msg (D_PUSH, "PUSH: Received control message: '%s'", BSTR (buffer));

  status = process_incoming_push_msg (c,
				      buffer,
				      c->options.pull,
				      pull_permission_mask (c),
				      &option_types_found);

  if (status == PUSH_MSG_ERROR)
    msg (D_PUSH_ERRORS, "WARNING: Received bad push/pull message: %s", BSTR (buffer));
  else if (status == PUSH_MSG_REPLY)
    {
      do_up (c, true, option_types_found); /* delay bringing tun/tap up until --push parms received from remote */
      event_timeout_clear (&c->c2.push_request_interval);
    }

  gc_free (&gc);
}

bool
send_push_request (struct context *c)
{
  return send_control_channel_string (c, "PUSH_REQUEST", D_PUSH);
}

#if P2MP_SERVER
bool
send_push_reply (struct context *c)
{
  struct gc_arena gc = gc_new ();
  struct buffer buf = alloc_buf_gc (MAX_PUSH_LIST_LEN + 256, &gc);
  bool ret = false;

  buf_printf (&buf, "PUSH_REPLY");

  if (c->options.push_list && strlen (c->options.push_list->options))
    buf_printf (&buf, ",%s", c->options.push_list->options);

  if (c->c2.push_ifconfig_defined && c->c2.push_ifconfig_local && c->c2.push_ifconfig_remote_netmask)
    buf_printf (&buf, ",ifconfig %s %s",
		print_in_addr_t (c->c2.push_ifconfig_local, 0, &gc),
		print_in_addr_t (c->c2.push_ifconfig_remote_netmask, 0, &gc));

  if (strlen (BSTR (&buf)) < MAX_PUSH_LIST_LEN)
    ret = send_control_channel_string (c, BSTR (&buf), D_PUSH);
  else
    msg (M_WARN, "Maximum length of --push buffer (%d) has been exceeded", MAX_PUSH_LIST_LEN);

  gc_free (&gc);
  return ret;
}

void
push_option (struct options *o, const char *opt, int msglevel)
{
  int len;
  bool first = false;

  if (!string_class (opt, CC_ANY, CC_COMMA))
    {
      msg (msglevel, "PUSH OPTION FAILED (illegal comma (',') in string): '%s'", opt);
    }
  else
    {
      if (!o->push_list)
	{
	  ALLOC_OBJ_CLEAR_GC (o->push_list, struct push_list, &o->gc);
	  first = true;
	}

      len = strlen (o->push_list->options);
      if (len + strlen (opt) + 2 >= MAX_PUSH_LIST_LEN)
	{
	  msg (msglevel, "Maximum length of --push buffer (%d) has been exceeded", MAX_PUSH_LIST_LEN);
	}
      else
	{
	  if (!first)
	    strcat (o->push_list->options, ",");
	  strcat (o->push_list->options, opt);
	}
    }
}

void
push_options (struct options *o, char **p, int msglevel, struct gc_arena *gc)
{
  const char **argv = make_extended_arg_array (p, gc);
  char *opt = print_argv (argv, gc, 0);
  push_option (o, opt, msglevel);
}

void
push_reset (struct options *o)
{
  o->push_list = NULL;
}
#endif

int
process_incoming_push_msg (struct context *c,
			   const struct buffer *buffer,
			   bool honor_received_options,
			   unsigned int permission_mask,
			   unsigned int *option_types_found)
{
  int ret = PUSH_MSG_ERROR;
  struct buffer buf = *buffer;

#if P2MP_SERVER
  if (buf_string_compare_advance (&buf, "PUSH_REQUEST"))
    {
      if (tls_authentication_status (c->c2.tls_multi, 0) == TLS_AUTHENTICATION_FAILED || c->c2.context_auth == CAS_FAILED)
	{
	  send_auth_failed (c);
	  ret = PUSH_MSG_AUTH_FAILURE;
	}
      else if (!c->c2.push_reply_deferred && c->c2.context_auth == CAS_SUCCEEDED)
	{
	  if (send_push_reply (c))
	    ret = PUSH_MSG_REQUEST;
	}
      else
	{
	  ret = PUSH_MSG_REQUEST_DEFERRED;
	}
    }
  else
#endif

  if (honor_received_options && buf_string_compare_advance (&buf, "PUSH_REPLY"))
    {
      const uint8_t ch = buf_read_u8 (&buf);
      if (ch == ',')
	{
	  pre_pull_restore (&c->options);
	  c->c2.pulled_options_string = string_alloc (BSTR (&buf), &c->c2.gc);
	  if (apply_push_options (&c->options,
				  &buf,
				  permission_mask,
				  option_types_found,
				  c->c2.es))
	    ret = PUSH_MSG_REPLY;
	}
      else if (ch == '\0')
	{
	  ret = PUSH_MSG_REPLY;
	}
      /* show_settings (&c->options); */
    }
  return ret;
}

#if P2MP_SERVER
/*
 * Remove iroutes from the push_list.
 */
void
remove_iroutes_from_push_route_list (struct options *o)
{
  if (o && o->push_list && o->iroutes)
    {
      struct gc_arena gc = gc_new ();
      struct push_list *pl;
      struct buffer in, out;
      char *line;
      bool first = true;

      /* prepare input and output buffers */
      ALLOC_OBJ_CLEAR_GC (pl, struct push_list, &gc);
      ALLOC_ARRAY_CLEAR_GC (line, char, MAX_PUSH_LIST_LEN, &gc);

      buf_set_read (&in, (const uint8_t*) o->push_list->options, strlen (o->push_list->options));
      buf_set_write (&out, (uint8_t*) pl->options, sizeof (pl->options));

      /* cycle through the push list */
      while (buf_parse (&in, ',', line, MAX_PUSH_LIST_LEN))
	{
	  char *p[MAX_PARMS];
	  bool copy = true;

	  /* parse the push item */
	  CLEAR (p);
	  if (parse_line (line, p, SIZE (p), "[PUSH_ROUTE_REMOVE]", 1, D_ROUTE_DEBUG, &gc))
	    {
	      /* is the push item a route directive? */
	      if (p[0] && !strcmp (p[0], "route") && !p[3])
		{
		  /* get route parameters */
		  bool status1, status2;
		  const in_addr_t network = getaddr (GETADDR_HOST_ORDER, p[1], 0, &status1, NULL);
		  const in_addr_t netmask = getaddr (GETADDR_HOST_ORDER, p[2] ? p[2] : "255.255.255.255", 0, &status2, NULL);

		  /* did route parameters parse correctly? */
		  if (status1 && status2)
		    {
		      const struct iroute *ir;

		      /* does route match an iroute? */
		      for (ir = o->iroutes; ir != NULL; ir = ir->next)
			{
			  if (network == ir->network && netmask == netbits_to_netmask (ir->netbits >= 0 ? ir->netbits : 32))
			    {
			      copy = false;
			      break;
			    }
			}
		    }
		}
	    }

	  /* should we copy the push item? */
	  if (copy)
	    {
	      if (!first)
		buf_printf (&out, ",");
	      buf_printf (&out, "%s", line);
	      first = false;
	    }
	  else
	    msg (D_PUSH, "REMOVE PUSH ROUTE: '%s'", line);
	}

#if 0
      msg (M_INFO, "BEFORE: '%s'", o->push_list->options);
      msg (M_INFO, "AFTER:  '%s'", pl->options);
#endif

      /* copy new push list back to options */
      *o->push_list = *pl;

      gc_free (&gc);
    }
}
#endif

#endif
