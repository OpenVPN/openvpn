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

#ifdef ENABLE_MANAGEMENT

#include "error.h"
#include "fdmisc.h"
#include "options.h"
#include "sig.h"
#include "event.h"
#include "otime.h"
#include "integer.h"
#include "misc.h"
#include "ssl.h"
#include "common.h"
#include "manage.h"

#include "memdbg.h"

#ifdef ENABLE_PKCS11
#include "pkcs11.h"
#endif

#define MANAGEMENT_ECHO_PULL_INFO 0

#if MANAGEMENT_ECHO_PULL_INFO
#define MANAGEMENT_ECHO_FLAGS LOG_PRINT_INTVAL
#else
#define MANAGEMENT_ECHO_FLAGS 0
#endif

/* tag for blank username/password */
static const char blank_up[] = "[[BLANK]]";

struct management *management; /* GLOBAL */

/* static forward declarations */
static void man_output_standalone (struct management *man, volatile int *signal_received);
static void man_reset_client_socket (struct management *man, const bool exiting);

static void
man_help ()
{
  msg (M_CLIENT, "Management Interface for %s", title_string);
  msg (M_CLIENT, "Commands:");
  msg (M_CLIENT, "auth-retry t           : Auth failure retry mode (none,interact,nointeract).");
  msg (M_CLIENT, "bytecount n            : Show bytes in/out, update every n secs (0=off).");
  msg (M_CLIENT, "echo [on|off] [N|all]  : Like log, but only show messages in echo buffer.");
  msg (M_CLIENT, "exit|quit              : Close management session.");
  msg (M_CLIENT, "forget-passwords       : Forget passwords entered so far.");
  msg (M_CLIENT, "help                   : Print this message.");
  msg (M_CLIENT, "hold [on|off|release]  : Set/show hold flag to on/off state, or"); 
  msg (M_CLIENT, "                         release current hold and start tunnel."); 
  msg (M_CLIENT, "kill cn                : Kill the client instance(s) having common name cn.");
  msg (M_CLIENT, "kill IP:port           : Kill the client instance connecting from IP:port.");
  msg (M_CLIENT, "load-stats             : Show global server load stats.");
  msg (M_CLIENT, "log [on|off] [N|all]   : Turn on/off realtime log display");
  msg (M_CLIENT, "                         + show last N lines or 'all' for entire history.");
  msg (M_CLIENT, "mute [n]               : Set log mute level to n, or show level if n is absent.");
  msg (M_CLIENT, "needok type action     : Enter confirmation for NEED-OK request of 'type',");
  msg (M_CLIENT, "                         where action = 'ok' or 'cancel'.");
  msg (M_CLIENT, "needstr type action    : Enter confirmation for NEED-STR request of 'type',");
  msg (M_CLIENT, "                         where action is reply string.");
  msg (M_CLIENT, "net                    : (Windows only) Show network info and routing table.");
  msg (M_CLIENT, "password type p        : Enter password p for a queried OpenVPN password.");
  msg (M_CLIENT, "pid                    : Show process ID of the current OpenVPN process.");
#ifdef ENABLE_PKCS11
  msg (M_CLIENT, "pkcs11-id-count        : Get number of available PKCS#11 identities.");
  msg (M_CLIENT, "pkcs11-id-get index    : Get PKCS#11 identity at index.");
#endif
#ifdef MANAGEMENT_DEF_AUTH
  msg (M_CLIENT, "client-auth CID KID    : Authenticate client-id/key-id CID/KID (MULTILINE)");
  msg (M_CLIENT, "client-auth-nt CID KID : Authenticate client-id/key-id CID/KID");
  msg (M_CLIENT, "client-deny CID KID R [CR] : Deny auth client-id/key-id CID/KID with log reason");
  msg (M_CLIENT, "                             text R and optional client reason text CR");
  msg (M_CLIENT, "client-kill CID        : Kill client instance CID");
  msg (M_CLIENT, "env-filter [level]     : Set env-var filter level");
#ifdef MANAGEMENT_PF
  msg (M_CLIENT, "client-pf CID          : Define packet filter for client CID (MULTILINE)");
#endif
#endif
  msg (M_CLIENT, "signal s               : Send signal s to daemon,");
  msg (M_CLIENT, "                         s = SIGHUP|SIGTERM|SIGUSR1|SIGUSR2.");
  msg (M_CLIENT, "state [on|off] [N|all] : Like log, but show state history.");
  msg (M_CLIENT, "status [n]             : Show current daemon status info using format #n.");
  msg (M_CLIENT, "test n                 : Produce n lines of output for testing/debugging.");
  msg (M_CLIENT, "username type u        : Enter username u for a queried OpenVPN username.");
  msg (M_CLIENT, "verb [n]               : Set log verbosity level to n, or show if n is absent.");
  msg (M_CLIENT, "version                : Show current version number.");
#if HTTP_PROXY_FALLBACK
  msg (M_CLIENT, "http-proxy-fallback <server> <port> [flags] : Enter dynamic HTTP proxy fallback info.");
  msg (M_CLIENT, "http-proxy-fallback-disable : Disable HTTP proxy fallback.");
#endif
  msg (M_CLIENT, "END");
}

static const char *
man_state_name (const int state)
{
  switch (state)
    {
    case OPENVPN_STATE_INITIAL:
      return "INITIAL";
    case OPENVPN_STATE_CONNECTING:
      return "CONNECTING";
    case OPENVPN_STATE_WAIT:
      return "WAIT";
    case OPENVPN_STATE_AUTH:
      return "AUTH";
    case OPENVPN_STATE_GET_CONFIG:
      return "GET_CONFIG";
    case OPENVPN_STATE_ASSIGN_IP:
      return "ASSIGN_IP";
    case OPENVPN_STATE_ADD_ROUTES:
      return "ADD_ROUTES";
    case OPENVPN_STATE_CONNECTED:
      return "CONNECTED";
    case OPENVPN_STATE_RECONNECTING:
      return "RECONNECTING";
    case OPENVPN_STATE_EXITING:
      return "EXITING";
    case OPENVPN_STATE_RESOLVE:
      return "RESOLVE";
    case OPENVPN_STATE_TCP_CONNECT:
      return "TCP_CONNECT";
    default:
      return "?";
    }
}

static void
man_welcome (struct management *man)
{
  msg (M_CLIENT, ">INFO:OpenVPN Management Interface Version %d -- type 'help' for more info",
       MANAGEMENT_VERSION);
  if (man->persist.special_state_msg)
    msg (M_CLIENT, "%s", man->persist.special_state_msg);
}

static inline bool
man_password_needed (struct management *man)
{
  return man->settings.up.defined && !man->connection.password_verified;
}

static void
man_check_password (struct management *man, const char *line)
{
  if (man_password_needed (man))
    {
      if (streq (line, man->settings.up.password))
	{
	  man->connection.password_verified = true;
	  msg (M_CLIENT, "SUCCESS: password is correct");
	  man_welcome (man);
	}
      else
	{
	  man->connection.password_verified = false;
	  msg (M_CLIENT, "ERROR: bad password");
	  if (++man->connection.password_tries >= MANAGEMENT_N_PASSWORD_RETRIES)
	    {
	      msg (M_WARN, "MAN: client connection rejected after %d failed password attempts",
		   MANAGEMENT_N_PASSWORD_RETRIES);
	      man->connection.halt = true;
	    }
	}
    }
}

static void
man_update_io_state (struct management *man)
{
  if (socket_defined (man->connection.sd_cli))
    {
      if (buffer_list_defined (man->connection.out))
	{
	  man->connection.state = MS_CC_WAIT_WRITE;
	}
      else
	{
	  man->connection.state = MS_CC_WAIT_READ;
	}
    }
}

static void
man_output_list_push_finalize (struct management *man)
{
  if (management_connected (man))
    {
      man_update_io_state (man);
      if (!man->persist.standalone_disabled)
	{
	  volatile int signal_received = 0;
	  man_output_standalone (man, &signal_received);
	}
    }
}

static void
man_output_list_push_str (struct management *man, const char *str)
{
  if (management_connected (man) && str)
    {
      buffer_list_push (man->connection.out, (const unsigned char *) str);
    }
}

static void
man_output_list_push (struct management *man, const char *str)
{
  man_output_list_push_str (man, str);
  man_output_list_push_finalize (man);
}

static void
man_prompt (struct management *man)
{
  if (man_password_needed (man))
    man_output_list_push (man, "ENTER PASSWORD:");
#if 0 /* should we use prompt? */
  else
    man_output_list_push (man, ">");
#endif
}

static void
man_delete_unix_socket (struct management *man)
{
#if UNIX_SOCK_SUPPORT
  if ((man->settings.flags & (MF_UNIX_SOCK|MF_CONNECT_AS_CLIENT)) == MF_UNIX_SOCK)
    socket_delete_unix (&man->settings.local_unix);
#endif
}

static void
man_close_socket (struct management *man, const socket_descriptor_t sd)
{
#ifndef WIN32
  /*
   * Windows doesn't need this because the ne32 event is permanently
   * enabled at struct management scope.
   */
  if (man->persist.callback.delete_event)
    (*man->persist.callback.delete_event) (man->persist.callback.arg, sd);
#endif
  openvpn_close_socket (sd);
}

static void
virtual_output_callback_func (void *arg, const unsigned int flags, const char *str)
{
  struct management *man = (struct management *) arg;
  static int recursive_level = 0; /* GLOBAL */
  bool did_push = false;

  if (!recursive_level) /* don't allow recursion */
    {
      struct gc_arena gc = gc_new ();
      struct log_entry e;
      const char *out = NULL;

      ++recursive_level;

      CLEAR (e);
      update_time ();
      e.timestamp = now;
      e.u.msg_flags = flags;
      e.string = str;

      if (flags & M_FATAL)
	man->persist.standalone_disabled = false;

      if (flags != M_CLIENT)
	log_history_add (man->persist.log, &e);

      if (!man_password_needed (man))
	{
	  if (flags == M_CLIENT)
	    out = log_entry_print (&e, LOG_PRINT_CRLF, &gc);
	  else if (man->connection.log_realtime)
	    out = log_entry_print (&e, LOG_PRINT_INT_DATE
				   |   LOG_PRINT_MSG_FLAGS
				   |   LOG_PRINT_LOG_PREFIX
				   |   LOG_PRINT_CRLF, &gc);
	  if (out)
	    {
	      man_output_list_push_str (man, out);
	      did_push = true;
	    }
	  if (flags & M_FATAL)
	    {
	      out = log_entry_print (&e, LOG_FATAL_NOTIFY|LOG_PRINT_CRLF, &gc);
	      if (out)
		{
		  man_output_list_push_str (man, out);
		  did_push = true;
		  man_reset_client_socket (man, true);
		}
	    }
	}

      --recursive_level;
      gc_free (&gc);
    }

  if (did_push)
    man_output_list_push_finalize (man);
}

/*
 * Given a signal, return the signal with possible remapping applied,
 * or -1 if the signal should be ignored.
 */
static int
man_mod_signal (const struct management *man, const int signum)
{
  const unsigned int flags = man->settings.mansig;
  int s = signum;
  if (s == SIGUSR1)
    {
      if (flags & MANSIG_MAP_USR1_TO_HUP)
	s = SIGHUP;
      if (flags & MANSIG_MAP_USR1_TO_TERM)
	s = SIGTERM;
    }
  if (flags & MANSIG_IGNORE_USR1_HUP)
    {
      if (s == SIGHUP || s == SIGUSR1)
	s = -1;
    }
  return s;
}

static void
man_signal (struct management *man, const char *name)
{
  const int sig = parse_signal (name);
  if (sig >= 0)
    {
      const int sig_mod = man_mod_signal (man, sig);
      if (sig_mod >= 0)
	{
	  throw_signal (sig_mod);
	  msg (M_CLIENT, "SUCCESS: signal %s thrown", signal_name (sig_mod, true));
	}
      else
	{
	  if (man->persist.special_state_msg)
	    msg (M_CLIENT, "%s", man->persist.special_state_msg);
	  else
	    msg (M_CLIENT, "ERROR: signal '%s' is currently ignored", name);
	}
    }
  else
    {
      msg (M_CLIENT, "ERROR: signal '%s' is not a known signal type", name);
    }
}

static void
man_status (struct management *man, const int version, struct status_output *so)
{
  if (man->persist.callback.status)
    {
      (*man->persist.callback.status) (man->persist.callback.arg, version, so);
    }
  else
    {
      msg (M_CLIENT, "ERROR: The 'status' command is not supported by the current daemon mode");
    }
}

static void
man_bytecount (struct management *man, const int update_seconds)
{
  if (update_seconds >= 0)
    man->connection.bytecount_update_seconds = update_seconds;
  else
    man->connection.bytecount_update_seconds = 0;
  msg (M_CLIENT, "SUCCESS: bytecount interval changed");
}

void
man_bytecount_output_client (struct management *man)
{
  char in[32];
  char out[32];
  /* do in a roundabout way to work around possible mingw or mingw-glibc bug */
  openvpn_snprintf (in, sizeof (in), counter_format, man->persist.bytes_in);
  openvpn_snprintf (out, sizeof (out), counter_format, man->persist.bytes_out);
  msg (M_CLIENT, ">BYTECOUNT:%s,%s", in, out);
  man->connection.bytecount_last_update = now;
}

#ifdef MANAGEMENT_DEF_AUTH

void
man_bytecount_output_server (struct management *man,
			     const counter_type *bytes_in_total,
			     const counter_type *bytes_out_total,
			     struct man_def_auth_context *mdac)
{
  char in[32];
  char out[32];
  /* do in a roundabout way to work around possible mingw or mingw-glibc bug */
  openvpn_snprintf (in, sizeof (in), counter_format, *bytes_in_total);
  openvpn_snprintf (out, sizeof (out), counter_format, *bytes_out_total);
  msg (M_CLIENT, ">BYTECOUNT_CLI:%lu,%s,%s", mdac->cid, in, out);
  mdac->bytecount_last_update = now;
}

#endif

static void
man_kill (struct management *man, const char *victim)
{
  struct gc_arena gc = gc_new ();

  if (man->persist.callback.kill_by_cn && man->persist.callback.kill_by_addr)
    {
      struct buffer buf;
      char p1[128];
      char p2[128];
      int n_killed;

      buf_set_read (&buf, (uint8_t*) victim, strlen (victim) + 1);
      buf_parse (&buf, ':', p1, sizeof (p1));
      buf_parse (&buf, ':', p2, sizeof (p2));

      if (strlen (p1) && strlen (p2))
	{
	  /* IP:port specified */
	  bool status;
	  const in_addr_t addr = getaddr (GETADDR_HOST_ORDER|GETADDR_MSG_VIRT_OUT, p1, 0, &status, NULL);
	  if (status)
	    {
	      const int port = atoi (p2);
	      if (port > 0 && port < 65536)
		{
		  n_killed = (*man->persist.callback.kill_by_addr) (man->persist.callback.arg, addr, port);
		  if (n_killed > 0)
		    {
		      msg (M_CLIENT, "SUCCESS: %d client(s) at address %s:%d killed",
			   n_killed,
			   print_in_addr_t (addr, 0, &gc),
			   port);
		    }
		  else
		    {
		      msg (M_CLIENT, "ERROR: client at address %s:%d not found",
			   print_in_addr_t (addr, 0, &gc),
			   port);
		    }
		}
	      else
		{
		  msg (M_CLIENT, "ERROR: port number is out of range: %s", p2);
		}
	    }
	  else
	    {
	      msg (M_CLIENT, "ERROR: error parsing IP address: %s", p1);
	    }
	}
      else if (strlen (p1))
	{
	  /* common name specified */
	  n_killed = (*man->persist.callback.kill_by_cn) (man->persist.callback.arg, p1);
	  if (n_killed > 0)
	    {
	      msg (M_CLIENT, "SUCCESS: common name '%s' found, %d client(s) killed", p1, n_killed);
	    }
	  else
	    {
	      msg (M_CLIENT, "ERROR: common name '%s' not found", p1);
	    }
	}
      else
	{
	  msg (M_CLIENT, "ERROR: kill parse");
	}
    }
  else
    {
      msg (M_CLIENT, "ERROR: The 'kill' command is not supported by the current daemon mode");
    }

  gc_free (&gc);
}

/*
 * General-purpose history command handler
 * for the log and echo commands.
 */
static void
man_history (struct management *man,
	     const char *parm,
	     const char *type,
	     struct log_history *log,
	     bool *realtime,
	     const unsigned int lep_flags)
{
  struct gc_arena gc = gc_new ();
  int n = 0;

  if (streq (parm, "on"))
    {
      *realtime = true;
      msg (M_CLIENT, "SUCCESS: real-time %s notification set to ON", type);
    }
  else if (streq (parm, "off"))
    {
      *realtime = false;
      msg (M_CLIENT, "SUCCESS: real-time %s notification set to OFF", type);
    }
  else if (streq (parm, "all") || (n = atoi (parm)) > 0)
    {
      const int size = log_history_size (log);
      const int start = (n ? n : size) - 1;
      int i;

      for (i = start; i >= 0; --i)
	{
	  const struct log_entry *e = log_history_ref (log, i);
	  if (e)
	    {
	      const char *out = log_entry_print (e, lep_flags, &gc);
	      virtual_output_callback_func (man, M_CLIENT, out);
	    }
	}
      msg (M_CLIENT, "END");
    }
  else
    {
      msg (M_CLIENT, "ERROR: %s parameter must be 'on' or 'off' or some number n or 'all'", type);
    }

  gc_free (&gc);
}

static void
man_log (struct management *man, const char *parm)
{
  man_history (man,
	       parm,
	       "log",
	       man->persist.log,
	       &man->connection.log_realtime,
	       LOG_PRINT_INT_DATE|LOG_PRINT_MSG_FLAGS);
}

static void
man_echo (struct management *man, const char *parm)
{
  man_history (man,
	       parm,
	       "echo",
	       man->persist.echo,
	       &man->connection.echo_realtime,
	       LOG_PRINT_INT_DATE|MANAGEMENT_ECHO_FLAGS);
}

static void
man_state (struct management *man, const char *parm)
{
  man_history (man,
	       parm,
	       "state",
	       man->persist.state,
	       &man->connection.state_realtime,
	       LOG_PRINT_INT_DATE|LOG_PRINT_STATE|
	       LOG_PRINT_LOCAL_IP|LOG_PRINT_REMOTE_IP);
}

static void
man_up_finalize (struct management *man)
{
  switch (man->connection.up_query_mode)
    {
    case UP_QUERY_DISABLED:
      man->connection.up_query.defined = false;
      break;
    case UP_QUERY_USER_PASS:
      if (strlen (man->connection.up_query.username) && strlen (man->connection.up_query.password))
	man->connection.up_query.defined = true;
      break;
    case UP_QUERY_PASS:
      if (strlen (man->connection.up_query.password))
	man->connection.up_query.defined = true;
      break;
    case UP_QUERY_NEED_OK:
      if (strlen (man->connection.up_query.password))
	man->connection.up_query.defined = true;
      break;
    case UP_QUERY_NEED_STR:
      if (strlen (man->connection.up_query.password))
	man->connection.up_query.defined = true;
      break;
    default:
      ASSERT (0);
    }
}

static void
man_query_user_pass (struct management *man,
		     const char *type,
		     const char *string,
		     const bool needed,
		     const char *prompt,
		     char *dest,
		     int len)
{
  if (needed)
    {
      ASSERT (man->connection.up_query_type);
      if (streq (man->connection.up_query_type, type))
	{
	  strncpynt (dest, string, len);
	  man_up_finalize (man);
	  msg (M_CLIENT, "SUCCESS: '%s' %s entered, but not yet verified",
	       type,
	       prompt);
	}
      else
	msg (M_CLIENT, "ERROR: %s of type '%s' entered, but we need one of type '%s'",
	     prompt,
	     type,
	     man->connection.up_query_type);
    }
  else
    {
      msg (M_CLIENT, "ERROR: no %s is currently needed at this time", prompt);
    }
}

static void
man_query_username (struct management *man, const char *type, const char *string)
{
  const bool needed = (man->connection.up_query_mode == UP_QUERY_USER_PASS && man->connection.up_query_type);
  man_query_user_pass (man, type, string, needed, "username", man->connection.up_query.username, USER_PASS_LEN);
}

static void
man_query_password (struct management *man, const char *type, const char *string)
{
  const bool needed = ((man->connection.up_query_mode == UP_QUERY_USER_PASS
			|| man->connection.up_query_mode == UP_QUERY_PASS)
		       && man->connection.up_query_type);
  if (!string[0]) /* allow blank passwords to be passed through using the blank_up tag */
    string = blank_up;
  man_query_user_pass (man, type, string, needed, "password", man->connection.up_query.password, USER_PASS_LEN);
}

static void
man_query_need_ok (struct management *man, const char *type, const char *action)
{
  const bool needed = ((man->connection.up_query_mode == UP_QUERY_NEED_OK) && man->connection.up_query_type);
  man_query_user_pass (man, type, action, needed, "needok-confirmation", man->connection.up_query.password, USER_PASS_LEN);
}

static void
man_query_need_str (struct management *man, const char *type, const char *action)
{
  const bool needed = ((man->connection.up_query_mode == UP_QUERY_NEED_STR) && man->connection.up_query_type);
  man_query_user_pass (man, type, action, needed, "needstr-string", man->connection.up_query.password, USER_PASS_LEN);
}

static void
man_forget_passwords (struct management *man)
{
#if defined(USE_CRYPTO) && defined(USE_SSL)
  ssl_purge_auth ();
  msg (M_CLIENT, "SUCCESS: Passwords were forgotten");
#endif
}

static void
man_net (struct management *man)
{
  if (man->persist.callback.show_net)
    {
      (*man->persist.callback.show_net) (man->persist.callback.arg, M_CLIENT);
    }
  else
    {
      msg (M_CLIENT, "ERROR: The 'net' command is not supported by the current daemon mode");
    }
}

#ifdef ENABLE_PKCS11

static void
man_pkcs11_id_count (struct management *man)
{
  msg (M_CLIENT, ">PKCS11ID-COUNT:%d", pkcs11_management_id_count ());
}

static void
man_pkcs11_id_get (struct management *man, const int index)
{
  char *id = NULL;
  char *base64 = NULL;

  if (pkcs11_management_id_get (index, &id, &base64))
    msg (M_CLIENT, ">PKCS11ID-ENTRY:'%d', ID:'%s', BLOB:'%s'", index, id, base64);
  else
    msg (M_CLIENT, ">PKCS11ID-ENTRY:'%d'", index);

  if (id != NULL)
    free (id);
  if (base64 != NULL)
    free (base64);
}

#endif

static void
man_hold (struct management *man, const char *cmd)
{
  if (cmd)
    {
      if (streq (cmd, "on"))
	{
	  man->settings.flags |= MF_HOLD;
	  msg (M_CLIENT, "SUCCESS: hold flag set to ON");
	}
      else if (streq (cmd, "off"))
	{
	  man->settings.flags &= ~MF_HOLD;
	  msg (M_CLIENT, "SUCCESS: hold flag set to OFF");
	}
      else if (streq (cmd, "release"))
	{
	  man->persist.hold_release = true;
	  msg (M_CLIENT, "SUCCESS: hold release succeeded");
	}
      else
	{
	  msg (M_CLIENT, "ERROR: bad hold command parameter");
	}
    }
  else
    msg (M_CLIENT, "SUCCESS: hold=%d", BOOL_CAST(man->settings.flags & MF_HOLD));
}

#ifdef MANAGEMENT_DEF_AUTH

static bool
parse_cid (const char *str, unsigned long *cid)
{
  if (sscanf (str, "%lu", cid) == 1)
    return true;
  else
    {
      msg (M_CLIENT, "ERROR: cannot parse CID");
      return false;
    }
}

static bool
parse_kid (const char *str, unsigned int *kid)
{
  if (sscanf (str, "%u", kid) == 1)
    return true;
  else
    {
      msg (M_CLIENT, "ERROR: cannot parse KID");
      return false;
    }
}

static void
in_extra_reset (struct man_connection *mc, const bool new)
{
  if (mc)
    {
      if (!new)
	{
	  mc->in_extra_cmd = IEC_UNDEF;
	  mc->in_extra_cid = 0;
	  mc->in_extra_kid = 0;
	}
      if (mc->in_extra)
	{
	  buffer_list_free (mc->in_extra);
	  mc->in_extra = NULL;
	}
      if (new)
	mc->in_extra = buffer_list_new (0);
    }
}

static void
in_extra_dispatch (struct management *man)
{
   switch (man->connection.in_extra_cmd)
    {
    case IEC_CLIENT_AUTH:
       if (man->persist.callback.client_auth)
	{
	  const bool status = (*man->persist.callback.client_auth)
	    (man->persist.callback.arg,
	     man->connection.in_extra_cid,
	     man->connection.in_extra_kid,
	     true,
	     NULL,
	     NULL,
	     man->connection.in_extra);
	  man->connection.in_extra = NULL;
	  if (status)
	    {
	      msg (M_CLIENT, "SUCCESS: client-auth command succeeded");
	    }
	  else
	    {
	      msg (M_CLIENT, "ERROR: client-auth command failed");
	    }
	}
      else
	{
	  msg (M_CLIENT, "ERROR: The client-auth command is not supported by the current daemon mode");
	}
      break;
#ifdef MANAGEMENT_PF
    case IEC_CLIENT_PF:
      if (man->persist.callback.client_pf)
	{
	  const bool status = (*man->persist.callback.client_pf)
	    (man->persist.callback.arg,
	     man->connection.in_extra_cid,
	     man->connection.in_extra);
	  man->connection.in_extra = NULL;
	  if (status)
	    {
	      msg (M_CLIENT, "SUCCESS: client-pf command succeeded");
	    }
	  else
	    {
	      msg (M_CLIENT, "ERROR: client-pf command failed");
	    }
	}
      else
	{
	  msg (M_CLIENT, "ERROR: The client-pf command is not supported by the current daemon mode");
	}
      break;
#endif
    }
   in_extra_reset (&man->connection, false);
}

static void
man_client_auth (struct management *man, const char *cid_str, const char *kid_str, const bool extra)
{
  struct man_connection *mc = &man->connection;
  mc->in_extra_cid = 0;
  mc->in_extra_kid = 0;
  if (parse_cid (cid_str, &mc->in_extra_cid)
      && parse_kid (kid_str, &mc->in_extra_kid))
    {
      mc->in_extra_cmd = IEC_CLIENT_AUTH;
      in_extra_reset (mc, true);
      if (!extra)
	in_extra_dispatch (man);
    }
}

static void
man_client_deny (struct management *man, const char *cid_str, const char *kid_str, const char *reason, const char *client_reason)
{
  unsigned long cid = 0;
  unsigned int kid = 0;
  if (parse_cid (cid_str, &cid) && parse_kid (kid_str, &kid))
    {
      if (man->persist.callback.client_auth)
	{
	  const bool status = (*man->persist.callback.client_auth)
	    (man->persist.callback.arg,
	     cid,
	     kid,
	     false,
	     reason,
	     client_reason,
	     NULL);
	  if (status)
	    {
	      msg (M_CLIENT, "SUCCESS: client-deny command succeeded");
	    }
	  else
	    {
	      msg (M_CLIENT, "ERROR: client-deny command failed");
	    }
	}
      else
	{
	  msg (M_CLIENT, "ERROR: The client-deny command is not supported by the current daemon mode");
	}
    }
}

static void
man_client_kill (struct management *man, const char *cid_str)
{
  unsigned long cid = 0;
  if (parse_cid (cid_str, &cid))
    {
      if (man->persist.callback.kill_by_cid)
	{
	  const bool status = (*man->persist.callback.kill_by_cid) (man->persist.callback.arg, cid);
	  if (status)
	    {
	      msg (M_CLIENT, "SUCCESS: client-kill command succeeded");
	    }
	  else
	    {
	      msg (M_CLIENT, "ERROR: client-kill command failed");
	    }
	}
      else
	{
	  msg (M_CLIENT, "ERROR: The client-kill command is not supported by the current daemon mode");
	}
    }
}

static void
man_client_n_clients (struct management *man)
{
  if (man->persist.callback.n_clients)
    {
      const int nclients = (*man->persist.callback.n_clients) (man->persist.callback.arg);
      msg (M_CLIENT, "SUCCESS: nclients=%d", nclients);
    }
  else
    {
      msg (M_CLIENT, "ERROR: The nclients command is not supported by the current daemon mode");
    }
}

static void
man_env_filter (struct management *man, const int level)
{
  man->connection.env_filter_level = level;
  msg (M_CLIENT, "SUCCESS: env_filter_level=%d", level);
}

#ifdef MANAGEMENT_PF

static void
man_client_pf (struct management *man, const char *cid_str)
{
  struct man_connection *mc = &man->connection;
  mc->in_extra_cid = 0;
  mc->in_extra_kid = 0;
  if (parse_cid (cid_str, &mc->in_extra_cid))
    {
      mc->in_extra_cmd = IEC_CLIENT_PF;
      in_extra_reset (mc, true);
    }
}

#endif
#endif

static void
man_load_stats (struct management *man)
{
  extern counter_type link_read_bytes_global;
  extern counter_type link_write_bytes_global;
  int nclients = 0;

  if (man->persist.callback.n_clients)
    nclients = (*man->persist.callback.n_clients) (man->persist.callback.arg);
  msg (M_CLIENT, "SUCCESS: nclients=%d,bytesin=" counter_format ",bytesout=" counter_format,
       nclients,
       link_read_bytes_global,
       link_write_bytes_global);
}

#define MN_AT_LEAST (1<<0)

static bool
man_need (struct management *man, const char **p, const int n, unsigned int flags)
{
  int i;
  ASSERT (p[0]);
  for (i = 1; i <= n; ++i)
    {
      if (!p[i])
	{
	  msg (M_CLIENT, "ERROR: the '%s' command requires %s%d parameter%s",
	       p[0],
	       (flags & MN_AT_LEAST) ? "at least " : "",
	       n,
	       n > 1 ? "s" : "");
	  return false;
	}
    }
  return true;
}

#if HTTP_PROXY_FALLBACK

static void
man_http_proxy_fallback (struct management *man, const char *server, const char *port, const char *flags)
{
  if (man->persist.callback.http_proxy_fallback_cmd)
    {
      const bool status = (*man->persist.callback.http_proxy_fallback_cmd)(man->persist.callback.arg, server, port, flags);
      if (status)
	{
	  msg (M_CLIENT, "SUCCESS: proxy-fallback command succeeded");
	}
      else
	{
	  msg (M_CLIENT, "ERROR: proxy-fallback command failed");
	}
    }
  else
    {
      msg (M_CLIENT, "ERROR: The proxy-fallback command is not supported by the current daemon mode");
    }
}

#endif

static void
man_dispatch_command (struct management *man, struct status_output *so, const char **p, const int nparms)
{
  struct gc_arena gc = gc_new ();

  ASSERT (p[0]);
  if (streq (p[0], "exit") || streq (p[0], "quit"))
    {
      man->connection.halt = true;
      goto done;
    }
  else if (streq (p[0], "help"))
    {
      man_help ();
    }
  else if (streq (p[0], "version"))
    {
      msg (M_CLIENT, "OpenVPN Version: %s", title_string);
      msg (M_CLIENT, "Management Version: %d", MANAGEMENT_VERSION);
      msg (M_CLIENT, "END");
    }
  else if (streq (p[0], "pid"))
    {
      msg (M_CLIENT, "SUCCESS: pid=%d", openvpn_getpid ());
    }
#ifdef MANAGEMENT_DEF_AUTH
  else if (streq (p[0], "nclients"))
    {
      man_client_n_clients (man);
    }
  else if (streq (p[0], "env-filter"))
    {
      int level = 0;
      if (p[1])
	level = atoi (p[1]);
      man_env_filter (man, level);
    }
#endif
  else if (streq (p[0], "signal"))
    {
      if (man_need (man, p, 1, 0))
	man_signal (man, p[1]);
    }
  else if (streq (p[0], "load-stats"))
    {
      man_load_stats (man);
    }
  else if (streq (p[0], "status"))
    {
      int version = 0;
      if (p[1])
	version = atoi (p[1]);
      man_status (man, version, so);
    }
  else if (streq (p[0], "kill"))
    {
      if (man_need (man, p, 1, 0))
	man_kill (man, p[1]);
    }
  else if (streq (p[0], "verb"))
    {
      if (p[1])
	{
	  const int level = atoi(p[1]);
	  if (set_debug_level (level, 0))
	    msg (M_CLIENT, "SUCCESS: verb level changed");
	  else
	    msg (M_CLIENT, "ERROR: verb level is out of range");
	}
      else
	msg (M_CLIENT, "SUCCESS: verb=%d", get_debug_level ());
    }
  else if (streq (p[0], "mute"))
    {
      if (p[1])
	{
	  const int level = atoi(p[1]);
	  if (set_mute_cutoff (level))
	    msg (M_CLIENT, "SUCCESS: mute level changed");
	  else
	    msg (M_CLIENT, "ERROR: mute level is out of range");
	}
      else
	msg (M_CLIENT, "SUCCESS: mute=%d", get_mute_cutoff ());
    }
  else if (streq (p[0], "auth-retry"))
    {
#if P2MP
      if (p[1])
	{
	  if (auth_retry_set (M_CLIENT, p[1]))
	    msg (M_CLIENT, "SUCCESS: auth-retry parameter changed");
	  else
	    msg (M_CLIENT, "ERROR: bad auth-retry parameter");
	}
      else
	msg (M_CLIENT, "SUCCESS: auth-retry=%s", auth_retry_print ());	
#else
      msg (M_CLIENT, "ERROR: auth-retry feature is unavailable");
#endif
    }
  else if (streq (p[0], "state"))
    {
      if (!p[1])
	{
	  man_state (man, "1");
	}
      else
	{
	  if (p[1])
	    man_state (man, p[1]);
	  if (p[2])
	    man_state (man, p[2]);
	}
    }
  else if (streq (p[0], "log"))
    {
      if (man_need (man, p, 1, MN_AT_LEAST))
	{
	  if (p[1])
	    man_log (man, p[1]);
	  if (p[2])
	    man_log (man, p[2]);
	}
    }
  else if (streq (p[0], "echo"))
    {
      if (man_need (man, p, 1, MN_AT_LEAST))
	{
	  if (p[1])
	    man_echo (man, p[1]);
	  if (p[2])
	    man_echo (man, p[2]);
	}
    }
  else if (streq (p[0], "username"))
    {
      if (man_need (man, p, 2, 0))
	man_query_username (man, p[1], p[2]);
    }
  else if (streq (p[0], "password"))
    {
      if (man_need (man, p, 2, 0))
	man_query_password (man, p[1], p[2]);
    }
  else if (streq (p[0], "forget-passwords"))
    {
      man_forget_passwords (man);
    }
  else if (streq (p[0], "needok"))
    {
      if (man_need (man, p, 2, 0))
	man_query_need_ok (man, p[1], p[2]);
    }
  else if (streq (p[0], "needstr"))
    {
      if (man_need (man, p, 2, 0))
	man_query_need_str (man, p[1], p[2]);
    }
  else if (streq (p[0], "net"))
    {
      man_net (man);
    }
  else if (streq (p[0], "hold"))
    {
      man_hold (man, p[1]);
    }
  else if (streq (p[0], "bytecount"))
    {
      if (man_need (man, p, 1, 0))
	man_bytecount (man, atoi(p[1]));
    }
#ifdef MANAGEMENT_DEF_AUTH
  else if (streq (p[0], "client-kill"))
    {
      if (man_need (man, p, 1, 0))
	man_client_kill (man, p[1]);
    }
  else if (streq (p[0], "client-deny"))
    {
      if (man_need (man, p, 3, MN_AT_LEAST))
	man_client_deny (man, p[1], p[2], p[3], p[4]);
    }
  else if (streq (p[0], "client-auth-nt"))
    {
      if (man_need (man, p, 2, 0))
	man_client_auth (man, p[1], p[2], false);
    }
  else if (streq (p[0], "client-auth"))
    {
      if (man_need (man, p, 2, 0))
	man_client_auth (man, p[1], p[2], true);
    }
#ifdef MANAGEMENT_PF
  else if (streq (p[0], "client-pf"))
    {
      if (man_need (man, p, 1, 0))
	man_client_pf (man, p[1]);
    }
#endif
#endif
#ifdef ENABLE_PKCS11
  else if (streq (p[0], "pkcs11-id-count"))
    {
      man_pkcs11_id_count (man);
    }
  else if (streq (p[0], "pkcs11-id-get"))
    {
      if (man_need (man, p, 1, 0))
	man_pkcs11_id_get (man, atoi(p[1]));
    }
#endif
#if HTTP_PROXY_FALLBACK
  else if (streq (p[0], "http-proxy-fallback"))
    {
      if (man_need (man, p, 2, MN_AT_LEAST))
	man_http_proxy_fallback (man, p[1], p[2], p[3]);
    }
  else if (streq (p[0], "http-proxy-fallback-disable"))
    {
      man_http_proxy_fallback (man, NULL, NULL, NULL);
    }
#endif
#if 1
  else if (streq (p[0], "test"))
    {
      if (man_need (man, p, 1, 0))
	{
	  int i;
	  const int n = atoi (p[1]);
	  for (i = 0; i < n; ++i)
	    {
	      msg (M_CLIENT, "[%d] The purpose of this command is to generate large amounts of output.", i);
	    }
	}
    }
#endif
  else
    {
      msg (M_CLIENT, "ERROR: unknown command, enter 'help' for more options");
    }

 done:
  gc_free (&gc);
}

#ifdef WIN32

static void
man_start_ne32 (struct management *man)
{
  switch (man->connection.state)
    {
    case MS_LISTEN:
      net_event_win32_start (&man->connection.ne32, FD_ACCEPT, man->connection.sd_top);
      break;
    case MS_CC_WAIT_READ:
    case MS_CC_WAIT_WRITE:
      net_event_win32_start (&man->connection.ne32, FD_READ|FD_WRITE|FD_CLOSE, man->connection.sd_cli);
      break;
    default:
      ASSERT (0);
    }  
}

static void
man_stop_ne32 (struct management *man)
{
  net_event_win32_stop (&man->connection.ne32);
}

#endif

static void
man_record_peer_info (struct management *man)
{
  struct gc_arena gc = gc_new ();
  if (man->settings.write_peer_info_file)
    {
      bool success = false;
#ifdef HAVE_GETSOCKNAME
      if (socket_defined (man->connection.sd_cli))
	{
	  struct sockaddr_in addr;
	  socklen_t addrlen = sizeof (addr);
	  int status;

	  CLEAR (addr);
	  status = getsockname (man->connection.sd_cli, (struct sockaddr *)&addr, &addrlen);
	  if (!status && addrlen == sizeof (addr))
	    {
	      const in_addr_t a = ntohl (addr.sin_addr.s_addr);
	      const int p = ntohs (addr.sin_port);
	      FILE *fp = fopen (man->settings.write_peer_info_file, "w");
	      if (fp)
		{
		  fprintf (fp, "%s\n%d\n", print_in_addr_t (a, 0, &gc), p);
		  if (!fclose (fp))
		    success = true;
		}
	    }
	}
#endif
      if (!success)
	{
	  msg (D_MANAGEMENT, "MANAGEMENT: failed to write peer info to file %s",
	       man->settings.write_peer_info_file);
	  throw_signal_soft (SIGTERM, "management-connect-failed");
	}
    }
  gc_free (&gc);
}

static void
man_connection_settings_reset (struct management *man)
{
  man->connection.state_realtime = false;
  man->connection.log_realtime = false;
  man->connection.echo_realtime = false;
  man->connection.bytecount_update_seconds = 0;
  man->connection.password_verified = false;
  man->connection.password_tries = 0;
  man->connection.halt = false;
  man->connection.state = MS_CC_WAIT_WRITE;
}

static void
man_new_connection_post (struct management *man, const char *description)
{
  struct gc_arena gc = gc_new ();

  set_nonblock (man->connection.sd_cli);
  set_cloexec (man->connection.sd_cli);

  man_connection_settings_reset (man);

#ifdef WIN32
  man_start_ne32 (man);
#endif

#if UNIX_SOCK_SUPPORT
  if (man->settings.flags & MF_UNIX_SOCK)
    {
      msg (D_MANAGEMENT, "MANAGEMENT: %s %s",
	   description,
	   sockaddr_unix_name (&man->settings.local_unix, "NULL"));
    }
  else
#endif
    msg (D_MANAGEMENT, "MANAGEMENT: %s %s",
	 description,
	 print_sockaddr (&man->settings.local, &gc));

  buffer_list_reset (man->connection.out);

  if (!man_password_needed (man))
    man_welcome (man);
  man_prompt (man);
  man_update_io_state (man);

  gc_free (&gc);
}

#if UNIX_SOCK_SUPPORT
static bool
man_verify_unix_peer_uid_gid (struct management *man, const socket_descriptor_t sd)
{
  if (socket_defined (sd) && (man->settings.client_uid != -1 || man->settings.client_gid != -1))
    {
      static const char err_prefix[] = "MANAGEMENT: unix domain socket client connection rejected --";
      int uid, gid;
      if (unix_socket_get_peer_uid_gid (man->connection.sd_cli, &uid, &gid))
	{
	  if (man->settings.client_uid != -1 && man->settings.client_uid != uid)
	    {
	      msg (D_MANAGEMENT, "%s UID of socket peer (%d) doesn't match required value (%d) as given by --management-client-user",
		   err_prefix, uid, man->settings.client_uid);
	      return false;
	    }
	  if (man->settings.client_gid != -1 && man->settings.client_gid != gid)
	    {
	      msg (D_MANAGEMENT, "%s GID of socket peer (%d) doesn't match required value (%d) as given by --management-client-group",
		   err_prefix, gid, man->settings.client_gid);
	      return false;
	    }
	}
      else
	{
	  msg (D_MANAGEMENT, "%s cannot get UID/GID of socket peer", err_prefix);
	  return false;
	}
    }
  return true;
}
#endif

static void
man_accept (struct management *man)
{
  struct link_socket_actual act;
  CLEAR (act);

  /*
   * Accept the TCP or Unix domain socket client.
   */
#if UNIX_SOCK_SUPPORT
  if (man->settings.flags & MF_UNIX_SOCK)
    {
      struct sockaddr_un remote;
      man->connection.sd_cli = socket_accept_unix (man->connection.sd_top, &remote);
      if (!man_verify_unix_peer_uid_gid (man, man->connection.sd_cli))
	sd_close (&man->connection.sd_cli);
    }
  else
#endif
    man->connection.sd_cli = socket_do_accept (man->connection.sd_top, &act, false);

  if (socket_defined (man->connection.sd_cli))
    {
      man->connection.remote = act.dest;

      if (socket_defined (man->connection.sd_top))
	{
#ifdef WIN32
	  man_stop_ne32 (man);
#endif
	}

      man_new_connection_post (man, "Client connected from");
    }
}

static void
man_listen (struct management *man)
{
  struct gc_arena gc = gc_new ();

  /*
   * Initialize state
   */
  man->connection.state = MS_LISTEN;
  man->connection.sd_cli = SOCKET_UNDEFINED;

  /*
   * Initialize listening socket
   */
  if (man->connection.sd_top == SOCKET_UNDEFINED)
    {
#if UNIX_SOCK_SUPPORT
      if (man->settings.flags & MF_UNIX_SOCK)
	{
	  man_delete_unix_socket (man);
	  man->connection.sd_top = create_socket_unix ();
	  socket_bind_unix (man->connection.sd_top, &man->settings.local_unix, "MANAGEMENT");
	}
      else
#endif
	{
	  man->connection.sd_top = create_socket_tcp ();
	  socket_bind (man->connection.sd_top, &man->settings.local, "MANAGEMENT");
	}

      /*
       * Listen for connection
       */
      if (listen (man->connection.sd_top, 1))
	msg (M_SOCKERR, "MANAGEMENT: listen() failed");

      /*
       * Set misc socket properties
       */
      set_nonblock (man->connection.sd_top);
      set_cloexec (man->connection.sd_top);

#if UNIX_SOCK_SUPPORT
      if (man->settings.flags & MF_UNIX_SOCK)
	{
	  msg (D_MANAGEMENT, "MANAGEMENT: unix domain socket listening on %s",
	       sockaddr_unix_name (&man->settings.local_unix, "NULL"));
	}
      else
#endif
	msg (D_MANAGEMENT, "MANAGEMENT: TCP Socket listening on %s",
	     print_sockaddr (&man->settings.local, &gc));
    }

#ifdef WIN32
  man_start_ne32 (man);
#endif
  
  gc_free (&gc);
}

static void
man_connect (struct management *man)
{
  struct gc_arena gc = gc_new ();
  int status;
  int signal_received = 0;

  /*
   * Initialize state
   */
  man->connection.state = MS_INITIAL;
  man->connection.sd_top = SOCKET_UNDEFINED;

#if UNIX_SOCK_SUPPORT
  if (man->settings.flags & MF_UNIX_SOCK)
    {
      man->connection.sd_cli = create_socket_unix ();
      status = socket_connect_unix (man->connection.sd_cli, &man->settings.local_unix);
      if (!status && !man_verify_unix_peer_uid_gid (man, man->connection.sd_cli))
	  {
#ifdef EPERM
	    status = EPERM;
#else
	    status = 1;
#endif
	    sd_close (&man->connection.sd_cli);
	  }
    }
  else
#endif
    {
      man->connection.sd_cli = create_socket_tcp ();
      status = openvpn_connect (man->connection.sd_cli,
				&man->settings.local,
				5,
				&signal_received);
    }

  if (signal_received)
    {
      throw_signal (signal_received);
      goto done;
    }

  if (status)
    {
#if UNIX_SOCK_SUPPORT
      if (man->settings.flags & MF_UNIX_SOCK)
	{
	  msg (D_LINK_ERRORS,
	       "MANAGEMENT: connect to unix socket %s failed: %s",
	       sockaddr_unix_name (&man->settings.local_unix, "NULL"),
	       strerror_ts (status, &gc));
	}
      else
#endif
      msg (D_LINK_ERRORS,
	   "MANAGEMENT: connect to %s failed: %s",
	   print_sockaddr (&man->settings.local, &gc),
	   strerror_ts (status, &gc));
      throw_signal_soft (SIGTERM, "management-connect-failed");
      goto done;
    }

  man_record_peer_info (man);
  man_new_connection_post (man, "Connected to management server at");

 done:
  gc_free (&gc);
}

static void
man_reset_client_socket (struct management *man, const bool exiting)
{
  if (socket_defined (man->connection.sd_cli))
    {
#ifdef WIN32
      man_stop_ne32 (man);
#endif
      man_close_socket (man, man->connection.sd_cli);
      man->connection.sd_cli = SOCKET_UNDEFINED;
      man->connection.state = MS_INITIAL;
      command_line_reset (man->connection.in);
      buffer_list_reset (man->connection.out);
#ifdef MANAGEMENT_DEF_AUTH
      in_extra_reset (&man->connection, false);
#endif
      msg (D_MANAGEMENT, "MANAGEMENT: Client disconnected");
    }
  if (!exiting)
    {
#if defined(USE_CRYPTO) && defined(USE_SSL)
      if (man->settings.flags & MF_FORGET_DISCONNECT)
	ssl_purge_auth ();
#endif
      if (man->settings.flags & MF_SIGNAL) {
      	  int mysig = man_mod_signal (man, SIGUSR1);
	  if (mysig >= 0)
	    {
	      msg (D_MANAGEMENT, "MANAGEMENT: Triggering management signal");
	      throw_signal_soft (mysig, "management-disconnect");
	    }
      }

      if (man->settings.flags & MF_CONNECT_AS_CLIENT)
	{
	  msg (D_MANAGEMENT, "MANAGEMENT: Triggering management exit");
	  throw_signal_soft (SIGTERM, "management-exit");
	}
      else
	man_listen (man);
    }
}

static void
man_process_command (struct management *man, const char *line)
{
  struct gc_arena gc = gc_new ();
  struct status_output *so;
  int nparms;
  char *parms[MAX_PARMS+1];

  CLEAR (parms);
  so = status_open (NULL, 0, -1, &man->persist.vout, 0);
#ifdef MANAGEMENT_DEF_AUTH
  in_extra_reset (&man->connection, false);
#endif

  if (man_password_needed (man))
    {
      man_check_password (man, line);
    }
  else
    {
      nparms = parse_line (line, parms, MAX_PARMS, "TCP", 0, M_CLIENT, &gc);
      if (parms[0] && streq (parms[0], "password"))
	msg (D_MANAGEMENT_DEBUG, "MANAGEMENT: CMD 'password [...]'");
      else if (!streq (line, "load-stats"))
	msg (D_MANAGEMENT_DEBUG, "MANAGEMENT: CMD '%s'", line);

#if 0
      /* DEBUGGING -- print args */
      {
	int i;
	for (i = 0; i < nparms; ++i)
	  msg (M_INFO, "[%d] '%s'", i, parms[i]);
      }
#endif

      if (nparms > 0)
	man_dispatch_command (man, so, (const char **)parms, nparms);
    }

  CLEAR (parms);
  status_close (so);
  gc_free (&gc);
}

static bool
man_io_error (struct management *man, const char *prefix)
{
  const int err = openvpn_errno_socket ();

  if (!ignore_sys_error (err))
    {
      struct gc_arena gc = gc_new ();
      msg (D_MANAGEMENT, "MANAGEMENT: TCP %s error: %s",
	   prefix,
	   strerror_ts (err, &gc));
      gc_free (&gc);
      return true;
    }
  else
    return false;
}

static int
man_read (struct management *man)
{
  /*
   * read command line from socket
   */
  unsigned char buf[256];
  int len = 0;

  len = recv (man->connection.sd_cli, buf, sizeof (buf), MSG_NOSIGNAL);
  if (len == 0)
    {
      man_reset_client_socket (man, false);
    }
  else if (len > 0)
    {
      bool processed_command = false;

      ASSERT (len <= (int) sizeof (buf));
      command_line_add (man->connection.in, buf, len);

      /*
       * Reset output object
       */
      buffer_list_reset (man->connection.out);

      /*
       * process command line if complete
       */
      {
	const unsigned char *line;
	while ((line = command_line_get (man->connection.in)))
	  {
#ifdef MANAGEMENT_DEF_AUTH
	    if (man->connection.in_extra)
	      {
		if (!strcmp ((char *)line, "END"))
		  {
		    in_extra_dispatch (man);
		    in_extra_reset (&man->connection, false);
		  }
		else
		  {
		    buffer_list_push (man->connection.in_extra, line);
		  }
	      }
	    else
#endif
	      man_process_command (man, (char *) line);
	    if (man->connection.halt)
	      break;
	    command_line_next (man->connection.in);
	    processed_command = true;
	  }
      }

      /*
       * Reset output state to MS_CC_WAIT_(READ|WRITE)
       */
      if (man->connection.halt)
	{
	  man_reset_client_socket (man, false);
	  len = 0;
	}
      else
	{
	  if (processed_command)
	    man_prompt (man);
	  man_update_io_state (man);
	}
    }
  else /* len < 0 */
    {
      if (man_io_error (man, "recv"))
	man_reset_client_socket (man, false);
    }
  return len;
}

static int
man_write (struct management *man)
{
  const int size_hint = 1024;
  int sent = 0;
  const struct buffer *buf;

  buffer_list_aggregate(man->connection.out, size_hint);
  buf = buffer_list_peek (man->connection.out);
  if (buf && BLEN (buf))
    {
      const int len = min_int (size_hint, BLEN (buf));
      sent = send (man->connection.sd_cli, BPTR (buf), len, MSG_NOSIGNAL);
      if (sent >= 0)
	{
	  buffer_list_advance (man->connection.out, sent);
	}
      else if (sent < 0)
	{
	  if (man_io_error (man, "send"))
	    man_reset_client_socket (man, false);
	}
    }

  /*
   * Reset output state to MS_CC_WAIT_(READ|WRITE)
   */
  man_update_io_state (man);

  return sent;
}

static void
man_connection_clear (struct man_connection *mc)
{
  CLEAR (*mc);

  /* set initial state */
  mc->state = MS_INITIAL;

  /* clear socket descriptors */
  mc->sd_top = SOCKET_UNDEFINED;
  mc->sd_cli = SOCKET_UNDEFINED;
}

static void
man_persist_init (struct management *man,
		  const int log_history_cache,
		  const int echo_buffer_size,
		  const int state_buffer_size)
{
  struct man_persist *mp = &man->persist;
  if (!mp->defined)
    {
      CLEAR (*mp);

      /* initialize log history store */
      mp->log = log_history_init (log_history_cache);  

      /*
       * Initialize virtual output object, so that functions
       * which write to a virtual_output object can be redirected
       * here to the management object.
       */
      mp->vout.func = virtual_output_callback_func;
      mp->vout.arg = man;
      mp->vout.flags_default = M_CLIENT;
      msg_set_virtual_output (&mp->vout);

      /*
       * Initialize --echo list
       */
      man->persist.echo = log_history_init (echo_buffer_size);

      /*
       * Initialize --state list
       */
      man->persist.state = log_history_init (state_buffer_size);

      mp->defined = true;
    }
}

static void
man_persist_close (struct man_persist *mp)
{
  if (mp->log)
    {
      msg_set_virtual_output (NULL);
      log_history_close (mp->log);
    }

  if (mp->echo)
    log_history_close (mp->echo);

  if (mp->state)
    log_history_close (mp->state);

  CLEAR (*mp);
}
      
static void
man_settings_init (struct man_settings *ms,
		   const char *addr,
		   const int port,
		   const char *pass_file,
		   const char *client_user,
		   const char *client_group,
		   const int log_history_cache,
		   const int echo_buffer_size,
		   const int state_buffer_size,
		   const char *write_peer_info_file,
		   const int remap_sigusr1,
		   const unsigned int flags)
{
  if (!ms->defined)
    {
      CLEAR (*ms);

      ms->flags = flags;
      ms->client_uid = -1;
      ms->client_gid = -1;

      /*
       * Get username/password
       */
      if (pass_file)
	get_user_pass (&ms->up, pass_file, "Management", GET_USER_PASS_PASSWORD_ONLY);

      /*
       * lookup client UID/GID if specified
       */
      if (client_user)
	{
	  struct user_state s;
	  get_user (client_user, &s);
	  ms->client_uid = user_state_uid (&s);
	  msg (D_MANAGEMENT, "MANAGEMENT: client_uid=%d", ms->client_uid);
	  ASSERT (ms->client_uid >= 0);
	}
      if (client_group)
	{
	  struct group_state s;
	  get_group (client_group, &s);
	  ms->client_gid = group_state_gid (&s);
	  msg (D_MANAGEMENT, "MANAGEMENT: client_gid=%d", ms->client_gid);
	  ASSERT (ms->client_gid >= 0);
	}

      ms->write_peer_info_file = string_alloc (write_peer_info_file, NULL);

#if UNIX_SOCK_SUPPORT
      if (ms->flags & MF_UNIX_SOCK)
	sockaddr_unix_init (&ms->local_unix, addr);
      else
#endif
	{
	  /*
	   * Initialize socket address
	   */
	  ms->local.sa.sin_family = AF_INET;
	  ms->local.sa.sin_addr.s_addr = 0;
	  ms->local.sa.sin_port = htons (port);

	  /*
	   * Run management over tunnel, or
	   * separate channel?
	   */
	  if (streq (addr, "tunnel") && !(flags & MF_CONNECT_AS_CLIENT))
	    {
	      ms->management_over_tunnel = true;
	    }
	  else
	    {
	      ms->local.sa.sin_addr.s_addr = getaddr
		(GETADDR_RESOLVE|GETADDR_WARN_ON_SIGNAL|GETADDR_FATAL, addr, 0, NULL, NULL);
	    }
	}
      
      /*
       * Log history and echo buffer may need to be resized
       */
      ms->log_history_cache = log_history_cache;
      ms->echo_buffer_size = echo_buffer_size;
      ms->state_buffer_size = state_buffer_size;

      /*
       * Set remap sigusr1 flags
       */
      if (remap_sigusr1 == SIGHUP)
	ms->mansig |= MANSIG_MAP_USR1_TO_HUP;
      else if (remap_sigusr1 == SIGTERM)
	ms->mansig |= MANSIG_MAP_USR1_TO_TERM;

      ms->defined = true;
    }
}

static void
man_settings_close (struct man_settings *ms)
{
  free (ms->write_peer_info_file);
  CLEAR (*ms);
}


static void
man_connection_init (struct management *man)
{
  if (man->connection.state == MS_INITIAL)
    {
#ifdef WIN32
      /*
       * This object is a sort of TCP/IP helper
       * for Windows.
       */
      net_event_win32_init (&man->connection.ne32);
#endif

      /*
       * Allocate helper objects for command line input and
       * command output from/to the socket.
       */
      man->connection.in = command_line_new (1024);
      man->connection.out = buffer_list_new (0);

      /*
       * Initialize event set for standalone usage, when we are
       * running outside of the primary event loop.
       */
      {
	int maxevents = 1;
	man->connection.es = event_set_init (&maxevents, EVENT_METHOD_FAST);
      }

      /*
       * Listen/connect socket
       */
      if (man->settings.flags & MF_CONNECT_AS_CLIENT)
	man_connect (man);
      else
	man_listen (man);
    }
}

static void
man_connection_close (struct management *man)
{
  struct man_connection *mc = &man->connection;

  if (mc->es)
    event_free (mc->es);
#ifdef WIN32
  net_event_win32_close (&mc->ne32);
#endif
  if (socket_defined (mc->sd_top))
    {
      man_close_socket (man, mc->sd_top);
      man_delete_unix_socket (man);
    }
  if (socket_defined (mc->sd_cli))
    man_close_socket (man, mc->sd_cli);
  if (mc->in)
    command_line_free (mc->in);
  if (mc->out)
    buffer_list_free (mc->out);
#ifdef MANAGEMENT_DEF_AUTH
  in_extra_reset (&man->connection, false);
#endif
  man_connection_clear (mc);
}

struct management *
management_init (void)
{
  struct management *man;
  ALLOC_OBJ_CLEAR (man, struct management);

  man_persist_init (man,
		    MANAGEMENT_LOG_HISTORY_INITIAL_SIZE,
		    MANAGEMENT_ECHO_BUFFER_SIZE,
		    MANAGEMENT_STATE_BUFFER_SIZE);

  man_connection_clear (&man->connection);

  return man;
}

bool
management_open (struct management *man,
		 const char *addr,
		 const int port,
		 const char *pass_file,
		 const char *client_user,
		 const char *client_group,
		 const int log_history_cache,
		 const int echo_buffer_size,
		 const int state_buffer_size,
		 const char *write_peer_info_file,
		 const int remap_sigusr1,
		 const unsigned int flags)
{
  bool ret = false;

  /*
   * Save the settings only if they have not
   * been saved before.
   */
  man_settings_init (&man->settings,
		     addr,
		     port,
		     pass_file,
		     client_user,
		     client_group,
		     log_history_cache,
		     echo_buffer_size,
		     state_buffer_size,
		     write_peer_info_file,
		     remap_sigusr1,
		     flags);

  /*
   * The log is initially sized to MANAGEMENT_LOG_HISTORY_INITIAL_SIZE,
   * but may be changed here.  Ditto for echo and state buffers.
   */
  log_history_resize (man->persist.log, man->settings.log_history_cache);
  log_history_resize (man->persist.echo, man->settings.echo_buffer_size);
  log_history_resize (man->persist.state, man->settings.state_buffer_size);

  /*
   * If connection object is uninitialized and we are not doing
   * over-the-tunnel management, then open (listening) connection.
   */
  if (man->connection.state == MS_INITIAL)
    {
      if (!man->settings.management_over_tunnel)
	{
	  man_connection_init (man);
	  ret = true;
	}
    }

  return ret;
}

void
management_close (struct management *man)
{
  man_connection_close (man);
  man_settings_close (&man->settings);
  man_persist_close (&man->persist);
  free (man);
}

void
management_set_callback (struct management *man,
			 const struct management_callback *cb)
{
  man->persist.standalone_disabled = true;
  man->persist.callback = *cb;
}

void
management_clear_callback (struct management *man)
{
  man->persist.standalone_disabled = false;
  man->persist.hold_release = false;
  CLEAR (man->persist.callback);
  man_output_list_push_finalize (man); /* flush output queue */
}

void
management_set_state (struct management *man,
		      const int state,
		      const char *detail,
		      const in_addr_t tun_local_ip,
		      const in_addr_t tun_remote_ip)
{
  if (man->persist.state && (!(man->settings.flags & MF_SERVER) || state < OPENVPN_STATE_CLIENT_BASE))
    {
      struct gc_arena gc = gc_new ();
      struct log_entry e;
      const char *out = NULL;

      update_time ();
      CLEAR (e);
      e.timestamp = now;
      e.u.state = state;
      e.string = detail;
      e.local_ip = tun_local_ip;
      e.remote_ip = tun_remote_ip;
      
      log_history_add (man->persist.state, &e);

      if (man->connection.state_realtime)
	out = log_entry_print (&e, LOG_PRINT_STATE_PREFIX
			       |   LOG_PRINT_INT_DATE
                               |   LOG_PRINT_STATE
			       |   LOG_PRINT_LOCAL_IP
			       |   LOG_PRINT_REMOTE_IP
                               |   LOG_PRINT_CRLF
			       |   LOG_ECHO_TO_LOG, &gc);

      if (out)
	man_output_list_push (man, out);

      gc_free (&gc);
    }
}

#ifdef MANAGEMENT_DEF_AUTH

static bool
env_filter_match (const char *env_str, const int env_filter_level)
{
  static const char *env_names[] = {
    "username=",
    "password=",
    "X509_0_CN=",
    "tls_serial_0=",
    "untrusted_ip=",
    "ifconfig_local=",
    "ifconfig_netmask=",
    "daemon_start_time=",
    "daemon_pid=",
    "dev=",
    "ifconfig_pool_remote_ip=",
    "ifconfig_pool_netmask=",
    "time_duration=",
    "bytes_sent=",
    "bytes_received="
  };
  if (env_filter_level >= 1)
    {
      size_t i;
      for (i = 0; i < SIZE(env_names); ++i)
	{
	  const char *en = env_names[i];
	  const size_t len = strlen(en);
	  if (strncmp(env_str, en, len) == 0)
	    return true;
	}
      return false;
    }
  else
    return true;
}

static void
man_output_env (const struct env_set *es, const bool tail, const int env_filter_level)
{
  if (es)
    {
      struct env_item *e;
      for (e = es->list; e != NULL; e = e->next)
	{
	  if (e->string && (!env_filter_level || env_filter_match(e->string, env_filter_level)))
	    msg (M_CLIENT, ">CLIENT:ENV,%s", e->string);
	}
    }
  if (tail)
    msg (M_CLIENT, ">CLIENT:ENV,END");
}

static void
man_output_extra_env (struct management *man)
{
  struct gc_arena gc = gc_new ();
  struct env_set *es = env_set_create (&gc);
  if (man->persist.callback.n_clients)
    {
      const int nclients = (*man->persist.callback.n_clients) (man->persist.callback.arg);
      setenv_int (es, "n_clients", nclients);
    }
  man_output_env (es, false, man->connection.env_filter_level);
  gc_free (&gc);
}

static bool
validate_peer_info_line(const char *line)
{
  uint8_t c;
  int state = 0;
  while ((c=*line++))
    {
      switch (state)
	{
	case 0:
	case 1:
	  if (c == '=' && state == 1)
	    state = 2;
	  else if (isalnum(c) || c == '_')
	    state = 1;
	  else
	    return false;
	case 2:
	  if (isprint(c))
	    ;
	  else
	    return false;
	}
    }
  return (state == 2);
}

static void
man_output_peer_info_env (struct management *man, struct man_def_auth_context *mdac)
{
  char line[256];
  if (man->persist.callback.get_peer_info)
    {
      const char *peer_info = (*man->persist.callback.get_peer_info) (man->persist.callback.arg, mdac->cid);
      if (peer_info)
	{
	  struct buffer buf;
	  buf_set_read (&buf, (const uint8_t *) peer_info, strlen(peer_info));
	  while (buf_parse (&buf, '\n', line, sizeof (line)))
	    {
	      chomp (line);
	      if (validate_peer_info_line(line))
		{
		  msg (M_CLIENT, ">CLIENT:ENV,%s", line);
		}
	      else
		msg (D_MANAGEMENT, "validation failed on peer_info line received from client");
	    }
	}
    }
}

void
management_notify_client_needing_auth (struct management *management,
				       const unsigned int mda_key_id,
				       struct man_def_auth_context *mdac,
				       const struct env_set *es)
{
  if (!(mdac->flags & DAF_CONNECTION_CLOSED))
    {
      const char *mode = "CONNECT";
      if (mdac->flags & DAF_CONNECTION_ESTABLISHED)
	mode = "REAUTH";
      msg (M_CLIENT, ">CLIENT:%s,%lu,%u", mode, mdac->cid, mda_key_id);
      man_output_extra_env (management);
      man_output_peer_info_env(management, mdac);
      man_output_env (es, true, management->connection.env_filter_level);
      mdac->flags |= DAF_INITIAL_AUTH;
    }
}

void
management_connection_established (struct management *management,
				   struct man_def_auth_context *mdac,
				   const struct env_set *es)
{
  mdac->flags |= DAF_CONNECTION_ESTABLISHED;
  msg (M_CLIENT, ">CLIENT:ESTABLISHED,%lu", mdac->cid);
  man_output_extra_env (management);
  man_output_env (es, true, management->connection.env_filter_level);
}

void
management_notify_client_close (struct management *management,
				struct man_def_auth_context *mdac,
				const struct env_set *es)
{
  if ((mdac->flags & DAF_INITIAL_AUTH) && !(mdac->flags & DAF_CONNECTION_CLOSED))
    {
      msg (M_CLIENT, ">CLIENT:DISCONNECT,%lu", mdac->cid);
      man_output_env (es, true, management->connection.env_filter_level);
      mdac->flags |= DAF_CONNECTION_CLOSED;
    }
}

void
management_learn_addr (struct management *management,
		       struct man_def_auth_context *mdac,
		       const struct mroute_addr *addr,
		       const bool primary)
{
  struct gc_arena gc = gc_new ();
  if ((mdac->flags & DAF_INITIAL_AUTH) && !(mdac->flags & DAF_CONNECTION_CLOSED))
    {
      msg (M_CLIENT, ">CLIENT:ADDRESS,%lu,%s,%d",
	   mdac->cid,
	   mroute_addr_print_ex (addr, MAPF_SUBNET, &gc),
	   BOOL_CAST (primary));
    }
  gc_free (&gc);
}

#endif

void
management_echo (struct management *man, const char *string, const bool pull)
{
  if (man->persist.echo)
    {
      struct gc_arena gc = gc_new ();
      struct log_entry e;
      const char *out = NULL;

      update_time ();
      CLEAR (e);
      e.timestamp = now;
      e.string = string;
      e.u.intval = BOOL_CAST (pull);

      log_history_add (man->persist.echo, &e);

      if (man->connection.echo_realtime)
	out = log_entry_print (&e, LOG_PRINT_INT_DATE|LOG_PRINT_ECHO_PREFIX|LOG_PRINT_CRLF|MANAGEMENT_ECHO_FLAGS, &gc);

      if (out)
	man_output_list_push (man, out);

      gc_free (&gc);
    }
}

void
management_post_tunnel_open (struct management *man, const in_addr_t tun_local_ip)
{
  /*
   * If we are running management over the tunnel,
   * this is the place to initialize the connection.
   */
  if (man->settings.management_over_tunnel
      && man->connection.state == MS_INITIAL)
    {
      /* listen on our local TUN/TAP IP address */
      man->settings.local.sa.sin_addr.s_addr = htonl (tun_local_ip);
      man_connection_init (man);
    }

}

void
management_pre_tunnel_close (struct management *man)
{
  if (man->settings.management_over_tunnel)
    man_connection_close (man);
}

void
management_auth_failure (struct management *man, const char *type, const char *reason)
{
  if (reason)
    msg (M_CLIENT, ">PASSWORD:Verification Failed: '%s' ['%s']", type, reason);
  else
    msg (M_CLIENT, ">PASSWORD:Verification Failed: '%s'", type);
}

static inline bool
man_persist_state (unsigned int *persistent, const int n)
{
  if (persistent)
    {
      if (*persistent == (unsigned int)n)
	return false;
      *persistent = n;
    }
  return true;
}

#ifdef WIN32

void
management_socket_set (struct management *man,
		       struct event_set *es,
		       void *arg,
		       unsigned int *persistent)
{
  if (man->connection.state != MS_INITIAL)
    {
      event_t ev = net_event_win32_get_event (&man->connection.ne32);
      net_event_win32_reset_write (&man->connection.ne32);

      switch (man->connection.state)
	{
	case MS_LISTEN:
	  if (man_persist_state (persistent, 1))
	    event_ctl (es, ev, EVENT_READ, arg);
	  break;
	case MS_CC_WAIT_READ:
	  if (man_persist_state (persistent, 2))
	    event_ctl (es, ev, EVENT_READ, arg);
	  break;
	case MS_CC_WAIT_WRITE:
	  if (man_persist_state (persistent, 3))
	    event_ctl (es, ev, EVENT_READ|EVENT_WRITE, arg);
	  break;
	default:
	  ASSERT (0);
	}
    }
}

void
management_io (struct management *man)
{
  if (man->connection.state != MS_INITIAL)
    {
      long net_events;
      net_event_win32_reset (&man->connection.ne32);
      net_events = net_event_win32_get_event_mask (&man->connection.ne32);

      if (net_events & FD_CLOSE)
	{
	  man_reset_client_socket (man, false);
	}
      else
	{
	  if (man->connection.state == MS_LISTEN)
	    {
	      if (net_events & FD_ACCEPT)
		{
		  man_accept (man);
		  net_event_win32_clear_selected_events (&man->connection.ne32, FD_ACCEPT);
		}
	    }
	  else if (man->connection.state == MS_CC_WAIT_READ || man->connection.state == MS_CC_WAIT_WRITE)
	    {
	      if (net_events & FD_READ)
		{
		  while (man_read (man) > 0)
		    ;
		  net_event_win32_clear_selected_events (&man->connection.ne32, FD_READ);
		}

	      if (net_events & FD_WRITE)
		{
		  int status;
		  status = man_write (man);
		  if (status < 0 && WSAGetLastError() == WSAEWOULDBLOCK)
		    {
		      net_event_win32_clear_selected_events (&man->connection.ne32, FD_WRITE);
		    }
		}
	    }
	}
    }
}

#else

void
management_socket_set (struct management *man,
		       struct event_set *es,
		       void *arg,
		       unsigned int *persistent)
{
  switch (man->connection.state)
    {
    case MS_LISTEN:
      if (man_persist_state (persistent, 1))
	event_ctl (es, man->connection.sd_top, EVENT_READ, arg);
      break;
    case MS_CC_WAIT_READ:
      if (man_persist_state (persistent, 2))
	event_ctl (es, man->connection.sd_cli, EVENT_READ, arg);
      break;
    case MS_CC_WAIT_WRITE:
      if (man_persist_state (persistent, 3))
	event_ctl (es, man->connection.sd_cli, EVENT_WRITE, arg);
      break;
    case MS_INITIAL:
      break;
    default:
      ASSERT (0);
    }
}

void
management_io (struct management *man)
{
  switch (man->connection.state)
    {
    case MS_LISTEN:
      man_accept (man);
      break;
    case MS_CC_WAIT_READ:
      man_read (man);
      break;
    case MS_CC_WAIT_WRITE:
      man_write (man);
      break;
    case MS_INITIAL:
      break;
    default:
      ASSERT (0);
    }
}

#endif

static inline bool
man_standalone_ok (const struct management *man)
{
  return !man->settings.management_over_tunnel && man->connection.state != MS_INITIAL;
}

static bool
man_check_for_signals (volatile int *signal_received)
{
  if (signal_received)
    {
      get_signal (signal_received);
      if (*signal_received)
	return true;
    }
  return false;
}

/*
 * Wait for socket I/O when outside primary event loop
 */
static int
man_block (struct management *man, volatile int *signal_received, const time_t expire)
{
  struct timeval tv;
  struct event_set_return esr;
  int status = -1;
  
  if (man_standalone_ok (man))
    {
      while (true)
	{
	  event_reset (man->connection.es);
	  management_socket_set (man, man->connection.es, NULL, NULL);
	  tv.tv_usec = 0;
	  tv.tv_sec = 1;
	  if (man_check_for_signals (signal_received))
	    {
	      status = -1;
	      break;
	    }
	  status = event_wait (man->connection.es, &tv, &esr, 1);
	  update_time ();
	  if (man_check_for_signals (signal_received))
	    {
	      status = -1;
	      break;
	    }

	  if (status > 0)
	    break;
	  else if (expire && now >= expire)
	    {
	      /* set SIGINT signal if expiration time exceeded */
	      status = 0;
	      if (signal_received)
		*signal_received = SIGINT;
	      break;
	    }
	}
    }
  return status;
}

/*
 * Perform management socket output outside primary event loop
 */
static void
man_output_standalone (struct management *man, volatile int *signal_received)
{
  if (man_standalone_ok (man))
    {
      while (man->connection.state == MS_CC_WAIT_WRITE)
	{
	  management_io (man);
	  if (man->connection.state == MS_CC_WAIT_WRITE)
	    man_block (man, signal_received, 0);
	  if (signal_received && *signal_received)
	    break;
	}
    }
}

/*
 * Process management event loop outside primary event loop
 */
static int
man_standalone_event_loop (struct management *man, volatile int *signal_received, const time_t expire)
{
  int status = -1;
  if (man_standalone_ok (man))
    {
      status = man_block (man, signal_received, expire);
      if (status > 0)
	management_io (man);
    }
  return status;
}

#define MWCC_PASSWORD_WAIT (1<<0)
#define MWCC_HOLD_WAIT     (1<<1)

/*
 * Block until client connects
 */
static void
man_wait_for_client_connection (struct management *man,
				volatile int *signal_received,
				const time_t expire,
				unsigned int flags)
{
  ASSERT (man_standalone_ok (man));
  if (man->connection.state == MS_LISTEN)
    {
      if (flags & MWCC_PASSWORD_WAIT)
	msg (D_MANAGEMENT, "Need password(s) from management interface, waiting...");
      if (flags & MWCC_HOLD_WAIT)
	msg (D_MANAGEMENT, "Need hold release from management interface, waiting...");
      do {
	man_standalone_event_loop (man, signal_received, expire);
	if (signal_received && *signal_received)
	  break;
      } while (man->connection.state == MS_LISTEN || man_password_needed (man));
    }
}

/*
 * Process the management event loop for sec seconds
 */
void
management_event_loop_n_seconds (struct management *man, int sec)
{
  if (man_standalone_ok (man))
    {
      volatile int signal_received = 0;
      const bool standalone_disabled_save = man->persist.standalone_disabled;
      time_t expire = 0;

      man->persist.standalone_disabled = false; /* This is so M_CLIENT messages will be correctly passed through msg() */

      /* set expire time */
      update_time ();
      if (sec)
	expire = now + sec;

      /* if no client connection, wait for one */
      man_wait_for_client_connection (man, &signal_received, expire, 0);
      if (signal_received)
	return;

      /* run command processing event loop */
      do
	{
	  man_standalone_event_loop (man, &signal_received, expire);
	  if (!signal_received)
	    man_check_for_signals (&signal_received);
	  if (signal_received)
	    return;
	} while (expire);

      /* revert state */
      man->persist.standalone_disabled = standalone_disabled_save;
    }
  else
    {
      sleep (sec);
    }
}

/*
 * Get a username/password from management channel in standalone mode.
 */
bool
management_query_user_pass (struct management *man,
			    struct user_pass *up,
			    const char *type,
			    const unsigned int flags)
{
  struct gc_arena gc = gc_new ();
  bool ret = false;

  if (man_standalone_ok (man))
    {
      volatile int signal_received = 0;
      const bool standalone_disabled_save = man->persist.standalone_disabled;
      struct buffer alert_msg = alloc_buf_gc (128, &gc);
      const char *alert_type = NULL;
      const char *prefix = NULL;
      unsigned int up_query_mode = 0;

      ret = true;
      man->persist.standalone_disabled = false; /* This is so M_CLIENT messages will be correctly passed through msg() */
      man->persist.special_state_msg = NULL;

      CLEAR (man->connection.up_query);

      if (flags & GET_USER_PASS_NEED_OK)
	{
	  up_query_mode = UP_QUERY_NEED_OK;
	  prefix= "NEED-OK";
	  alert_type = "confirmation";
	}
      else if (flags & GET_USER_PASS_NEED_STR)
        {
	  up_query_mode = UP_QUERY_NEED_STR;
	  prefix= "NEED-STR";
	  alert_type = "string";
	}
      else if (flags & GET_USER_PASS_PASSWORD_ONLY)
	{
	  up_query_mode = UP_QUERY_PASS;
	  prefix = "PASSWORD";
	  alert_type = "password";
	}
      else
	{
	  up_query_mode = UP_QUERY_USER_PASS;
	  prefix = "PASSWORD";
	  alert_type = "username/password";
	}
      buf_printf (&alert_msg, ">%s:Need '%s' %s",
		  prefix,
		  type,
		  alert_type);

      if (flags & (GET_USER_PASS_NEED_OK | GET_USER_PASS_NEED_STR))
	buf_printf (&alert_msg, " MSG:%s", up->username);

      man_wait_for_client_connection (man, &signal_received, 0, MWCC_PASSWORD_WAIT);
      if (signal_received)
	ret = false;

      if (ret)
	{
	  man->persist.special_state_msg = BSTR (&alert_msg);
	  msg (M_CLIENT, "%s", man->persist.special_state_msg);

	  /* tell command line parser which info we need */
	  man->connection.up_query_mode = up_query_mode;
	  man->connection.up_query_type = type;

	  /* run command processing event loop until we get our username/password */
	  do
	    {
	      man_standalone_event_loop (man, &signal_received, 0);
	      if (!signal_received)
		man_check_for_signals (&signal_received);
	      if (signal_received)
		{
		  ret = false;
		  break;
		}
	    } while (!man->connection.up_query.defined);
	}

      /* revert state */
      man->connection.up_query_mode = UP_QUERY_DISABLED;
      man->connection.up_query_type = NULL;
      man->persist.standalone_disabled = standalone_disabled_save;
      man->persist.special_state_msg = NULL;

      /* pass through blank passwords */
      if (!strcmp (man->connection.up_query.password, blank_up))
	CLEAR (man->connection.up_query.password);

      /*
       * Transfer u/p to return object, zero any record
       * we hold in the management object.
       */
      if (ret)
	{
	  man->connection.up_query.nocache = up->nocache; /* preserve caller's nocache setting */
	  *up = man->connection.up_query;
	}
      CLEAR (man->connection.up_query);
    }

  gc_free (&gc);
  return ret;
}

/*
 * Return true if management_hold() would block
 */
bool
management_would_hold (struct management *man)
{
  return (man->settings.flags & MF_HOLD) && !man->persist.hold_release && man_standalone_ok (man);
}

/*
 * Return true if (from the management interface's perspective) OpenVPN should
 * daemonize.
 */
bool
management_should_daemonize (struct management *man)
{
  return management_would_hold (man) || (man->settings.flags & MF_QUERY_PASSWORDS);
}

/*
 * If the hold flag is enabled, hibernate until a management client releases the hold.
 * Return true if the caller should not sleep for an additional time interval.
 */
bool
management_hold (struct management *man)
{
  if (management_would_hold (man))
    {
      volatile int signal_received = 0;
      const bool standalone_disabled_save = man->persist.standalone_disabled;

      man->persist.standalone_disabled = false; /* This is so M_CLIENT messages will be correctly passed through msg() */
      man->persist.special_state_msg = NULL;
      man->settings.mansig |= MANSIG_IGNORE_USR1_HUP;

      man_wait_for_client_connection (man, &signal_received, 0, MWCC_HOLD_WAIT);

      if (!signal_received)
	{
	  man->persist.special_state_msg = ">HOLD:Waiting for hold release";
	  msg (M_CLIENT, "%s", man->persist.special_state_msg);

	  /* run command processing event loop until we get our username/password */
	  do
	    {
	      man_standalone_event_loop (man, &signal_received, 0);
	      if (!signal_received)
		man_check_for_signals (&signal_received);
	      if (signal_received)
		break;
	    } while (!man->persist.hold_release);
	}

      /* revert state */
      man->persist.standalone_disabled = standalone_disabled_save;
      man->persist.special_state_msg = NULL;
      man->settings.mansig &= ~MANSIG_IGNORE_USR1_HUP;

      return true;
    }
  return false;
}

/*
 * struct command_line
 */

struct command_line *
command_line_new (const int buf_len)
{
  struct command_line *cl;
  ALLOC_OBJ_CLEAR (cl, struct command_line);
  cl->buf = alloc_buf (buf_len);
  cl->residual = alloc_buf (buf_len);
  return cl;
}

void
command_line_reset (struct command_line *cl)
{
  buf_clear (&cl->buf);
  buf_clear (&cl->residual);
}

void
command_line_free (struct command_line *cl)
{
  command_line_reset (cl);
  free_buf (&cl->buf);
  free_buf (&cl->residual);
  free (cl);
}

void
command_line_add (struct command_line *cl, const unsigned char *buf, const int len)
{
  int i;
  for (i = 0; i < len; ++i)
    {
      if (buf[i] && (isprint(buf[i]) || buf[i] == '\n'))
	{
	  if (!buf_write_u8 (&cl->buf, buf[i]))
	    buf_clear (&cl->buf);
	}
    }
}

const unsigned char *
command_line_get (struct command_line *cl)
{
  int i;
  const unsigned char *ret = NULL;

  i = buf_substring_len (&cl->buf, '\n');
  if (i >= 0)
    {
      buf_copy_excess (&cl->residual, &cl->buf, i);
      buf_chomp (&cl->buf);
      ret = (const unsigned char *) BSTR (&cl->buf);
    }
  return ret;
}

void
command_line_next (struct command_line *cl)
{
  buf_clear (&cl->buf);
  buf_copy (&cl->buf, &cl->residual);
  buf_clear (&cl->residual);
}

/*
 * struct log_entry
 */

const char *
log_entry_print (const struct log_entry *e, unsigned int flags, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (ERR_BUF_SIZE, gc);
  if (flags & LOG_FATAL_NOTIFY)
    buf_printf (&out, ">FATAL:");    
  if (flags & LOG_PRINT_LOG_PREFIX)
    buf_printf (&out, ">LOG:");
  if (flags & LOG_PRINT_ECHO_PREFIX)
    buf_printf (&out, ">ECHO:");
  if (flags & LOG_PRINT_STATE_PREFIX)
    buf_printf (&out, ">STATE:");
  if (flags & LOG_PRINT_INT_DATE)
    buf_printf (&out, "%u,", (unsigned int)e->timestamp);
  if (flags & LOG_PRINT_MSG_FLAGS)
    buf_printf (&out, "%s,", msg_flags_string (e->u.msg_flags, gc));
  if (flags & LOG_PRINT_STATE)
    buf_printf (&out, "%s,", man_state_name (e->u.state));
  if (flags & LOG_PRINT_INTVAL)
    buf_printf (&out, "%d,", e->u.intval);
  if (e->string)
    buf_printf (&out, "%s", e->string);
  if (flags & LOG_PRINT_LOCAL_IP)
    buf_printf (&out, ",%s", print_in_addr_t (e->local_ip, IA_EMPTY_IF_UNDEF, gc));
  if (flags & LOG_PRINT_REMOTE_IP)
    buf_printf (&out, ",%s", print_in_addr_t (e->remote_ip, IA_EMPTY_IF_UNDEF, gc));
  if (flags & LOG_ECHO_TO_LOG)
    msg (D_MANAGEMENT, "MANAGEMENT: %s", BSTR (&out));
  if (flags & LOG_PRINT_CRLF)
    buf_printf (&out, "\r\n");
  return BSTR (&out);
}

static void
log_entry_free_contents (struct log_entry *e)
{
  if (e->string)
    free ((char *)e->string);
  CLEAR (*e);
}

/*
 * struct log_history
 */

static inline int
log_index (const struct log_history *h, int i)
{
  return modulo_add (h->base, i, h->capacity);
}

static void
log_history_obj_init (struct log_history *h, int capacity)
{
  CLEAR (*h);
  h->capacity = capacity;
  ALLOC_ARRAY_CLEAR (h->array, struct log_entry, capacity);
}

struct log_history *
log_history_init (const int capacity)
{
  struct log_history *h;
  ASSERT (capacity > 0);
  ALLOC_OBJ (h, struct log_history);
  log_history_obj_init (h, capacity);
  return h;
}

static void
log_history_free_contents (struct log_history *h)
{
  int i;
  for (i = 0; i < h->size; ++i)
    log_entry_free_contents (&h->array[log_index(h, i)]);
  free (h->array);
}

void
log_history_close (struct log_history *h)
{
  log_history_free_contents (h);
  free (h);
}

void
log_history_add (struct log_history *h, const struct log_entry *le)
{
  struct log_entry *e;
  ASSERT (h->size >= 0 && h->size <= h->capacity);
  if (h->size == h->capacity)
    {
      e = &h->array[h->base];
      log_entry_free_contents (e);
      h->base = log_index (h, 1);
    }
  else
    {
      e = &h->array[log_index(h, h->size)];
      ++h->size;
    }

  *e = *le;
  e->string = string_alloc (le->string, NULL);
}

void
log_history_resize (struct log_history *h, const int capacity)
{
  if (capacity != h->capacity)
    {
      struct log_history newlog;
      int i;

      ASSERT (capacity > 0);
      log_history_obj_init (&newlog, capacity);

      for (i = 0; i < h->size; ++i)
	log_history_add (&newlog, &h->array[log_index(h, i)]);
			 
      log_history_free_contents (h);
      *h = newlog;
    }
}

const struct log_entry *
log_history_ref (const struct log_history *h, const int index)
{
  if (index >= 0 && index < h->size)
    return &h->array[log_index(h, (h->size - 1) - index)];
  else
    return NULL;
}

#if HTTP_PROXY_FALLBACK

void
management_http_proxy_fallback_notify (struct management *man, const char *type, const char *remote_ip_hint)
{
  if (remote_ip_hint)
    msg (M_CLIENT, ">PROXY:%s,%s", type, remote_ip_hint);
  else
    msg (M_CLIENT, ">PROXY:%s", type);
}

#endif /* HTTP_PROXY_FALLBACK */

#else
static void dummy(void) {}
#endif /* ENABLE_MANAGEMENT */
