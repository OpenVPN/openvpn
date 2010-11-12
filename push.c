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
  connection_list_set_no_advance(&c->options);
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
	{
	  const char *reason = NULL;
	  struct buffer buf = *buffer;
	  if (buf_string_compare_advance (&buf, "AUTH_FAILED,") && BLEN (&buf))
	    reason = BSTR (&buf);
	  management_auth_failure (management, UP_TYPE_AUTH, reason);
	} else
#endif
	{
#ifdef ENABLE_CLIENT_CR
	  struct buffer buf = *buffer;
	  if (buf_string_match_head_str (&buf, "AUTH_FAILED,CRV1:") && BLEN (&buf))
	    {
	      buf_advance (&buf, 12); /* Length of "AUTH_FAILED," substring */
	      ssl_put_auth_challenge (BSTR (&buf));
	    }
#endif
	}
    }
}

/*
 * Act on received restart message from server
 */
void
server_pushed_restart (struct context *c, const struct buffer *buffer)
{
  if (c->options.pull)
    {
      msg (D_STREAM_ERRORS, "Connection reset command was pushed by server");
      c->sig->signal_received = SIGUSR1; /* SOFT-SIGUSR1 -- server-pushed connection reset */
      c->sig->signal_text = "server-pushed-connection-reset";
    }
}

#if P2MP_SERVER

/*
 * Send auth failed message from server to client.
 */
void
send_auth_failed (struct context *c, const char *client_reason)
{
  struct gc_arena gc = gc_new ();
  static const char auth_failed[] = "AUTH_FAILED";
  size_t len;

  schedule_exit (c, c->options.scheduled_exit_interval, SIGTERM);

  len = (client_reason ? strlen(client_reason)+1 : 0) + sizeof(auth_failed);
  if (len > PUSH_BUNDLE_SIZE)
    len = PUSH_BUNDLE_SIZE;

  {
    struct buffer buf = alloc_buf_gc (len, &gc);
    buf_printf (&buf, auth_failed);
    if (client_reason)
      buf_printf (&buf, ",%s", client_reason);
    send_control_channel_string (c, BSTR (&buf), D_PUSH);
  }

  gc_free (&gc);
}

/*
 * Send restart message from server to client.
 */
void
send_restart (struct context *c)
{
  schedule_exit (c, c->options.scheduled_exit_interval, SIGTERM);
  send_control_channel_string (c, "RESTART", D_PUSH);
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
  else if (status == PUSH_MSG_REPLY || status == PUSH_MSG_CONTINUATION)
    {
      if (status == PUSH_MSG_REPLY)
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
  struct buffer buf = alloc_buf_gc (PUSH_BUNDLE_SIZE, &gc);
  struct push_entry *e = c->options.push_list.head;
  bool multi_push = false;
  static char cmd[] = "PUSH_REPLY";
  const int extra = 64; /* extra space for possible trailing ifconfig and push-continuation */
  const int safe_cap = BCAP (&buf) - extra;
  bool push_sent = false;

  buf_printf (&buf, "%s", cmd);

  while (e)
    {
      if (e->enable)
	{
	  const int l = strlen (e->option);
	  if (BLEN (&buf) + l >= safe_cap)
	    {
	      buf_printf (&buf, ",push-continuation 2");
	      {
		const bool status = send_control_channel_string (c, BSTR (&buf), D_PUSH);
		if (!status)
		  goto fail;
		push_sent = true;
		multi_push = true;
		buf_reset_len (&buf);
		buf_printf (&buf, "%s", cmd);
	      }
	    }
	  if (BLEN (&buf) + l >= safe_cap)
	    {
	      msg (M_WARN, "--push option is too long");
	      goto fail;
	    }
	  buf_printf (&buf, ",%s", e->option);
	}
      e = e->next;
    }

  if (c->c2.push_ifconfig_defined && c->c2.push_ifconfig_local && c->c2.push_ifconfig_remote_netmask)
    buf_printf (&buf, ",ifconfig %s %s",
		print_in_addr_t (c->c2.push_ifconfig_local, 0, &gc),
		print_in_addr_t (c->c2.push_ifconfig_remote_netmask, 0, &gc));
  if (multi_push)
    buf_printf (&buf, ",push-continuation 1");

  if (BLEN (&buf) > sizeof(cmd)-1)
    {
      const bool status = send_control_channel_string (c, BSTR (&buf), D_PUSH);
      if (!status)
        goto fail;
      push_sent = true;
    }

  /* If nothing have been pushed, send an empty push,
   * as the client is expecting a response
   */
  if (!push_sent)
    {
      bool status = false;

      buf_reset_len (&buf);
      buf_printf (&buf, "%s", cmd);
      status = send_control_channel_string (c, BSTR(&buf), D_PUSH);
      if (!status)
	goto fail;
    }

  gc_free (&gc);
  return true;

 fail:
  gc_free (&gc);
  return false;
}

static void
push_option_ex (struct options *o, const char *opt, bool enable, int msglevel)
{
  if (!string_class (opt, CC_ANY, CC_COMMA))
    {
      msg (msglevel, "PUSH OPTION FAILED (illegal comma (',') in string): '%s'", opt);
    }
  else
    {
      struct push_entry *e;
      ALLOC_OBJ_CLEAR_GC (e, struct push_entry, &o->gc);
      e->enable = true;
      e->option = opt;
      if (o->push_list.head)
	{
	  ASSERT(o->push_list.tail);
	  o->push_list.tail->next = e;
	  o->push_list.tail = e;
	}
      else
	{
	  ASSERT(!o->push_list.tail);
	  o->push_list.head = e;
	  o->push_list.tail = e;
	}
    }
}

void
push_option (struct options *o, const char *opt, int msglevel)
{
  push_option_ex (o, opt, true, msglevel);
}

void
clone_push_list (struct options *o)
{
  if (o->push_list.head)
    {
      const struct push_entry *e = o->push_list.head;
      push_reset (o);
      while (e)
	{
	  push_option_ex (o, string_alloc (e->option, &o->gc), true, M_FATAL);
	  e = e->next;
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
  CLEAR (o->push_list);
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
	  const char *client_reason = tls_client_reason (c->c2.tls_multi);
	  send_auth_failed (c, client_reason);
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
	  struct buffer buf_orig = buf;
	  if (!c->c2.did_pre_pull_restore)
	    {
	      pre_pull_restore (&c->options);
	      md5_state_init (&c->c2.pulled_options_state);
	      c->c2.did_pre_pull_restore = true;
	    }
	  if (apply_push_options (&c->options,
				  &buf,
				  permission_mask,
				  option_types_found,
				  c->c2.es))
	    switch (c->options.push_continuation)
	      {
	      case 0:
	      case 1:
		md5_state_update (&c->c2.pulled_options_state, BPTR(&buf_orig), BLEN(&buf_orig));
		md5_state_final (&c->c2.pulled_options_state, &c->c2.pulled_options_digest);
		ret = PUSH_MSG_REPLY;
		break;
	      case 2:
		md5_state_update (&c->c2.pulled_options_state, BPTR(&buf_orig), BLEN(&buf_orig));
		ret = PUSH_MSG_CONTINUATION;
		break;
	      }
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
  if (o && o->push_list.head && o->iroutes)
    {
      struct gc_arena gc = gc_new ();
      struct push_entry *e = o->push_list.head;

      /* cycle through the push list */
      while (e)
	{
	  char *p[MAX_PARMS];
	  bool enable = true;

	  /* parse the push item */
	  CLEAR (p);
	  if (parse_line (e->option, p, SIZE (p), "[PUSH_ROUTE_REMOVE]", 1, D_ROUTE_DEBUG, &gc))
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
			      enable = false;
			      break;
			    }
			}
		    }
		}
	    }

	  /* should we copy the push item? */
	  e->enable = enable;
	  if (!enable)
	    msg (D_PUSH, "REMOVE PUSH ROUTE: '%s'", e->option);

	  e = e->next;
	}

      gc_free (&gc);
    }
}

#endif

#endif
