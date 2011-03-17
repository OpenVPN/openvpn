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

#ifndef FORWARD_INLINE_H
#define FORWARD_INLINE_H

/*
 * Inline functions
 */

/*
 * Does TLS session need service?
 */
static inline void
check_tls (struct context *c)
{
#if defined(USE_CRYPTO) && defined(USE_SSL)
  void check_tls_dowork (struct context *c);
  if (c->c2.tls_multi)
    check_tls_dowork (c);
#endif
}

/*
 * TLS errors are fatal in TCP mode.
 * Also check for --tls-exit trigger.
 */
static inline void
check_tls_errors (struct context *c)
{
#if defined(USE_CRYPTO) && defined(USE_SSL)
  void check_tls_errors_co (struct context *c);
  void check_tls_errors_nco (struct context *c);
  if (c->c2.tls_multi && c->c2.tls_exit_signal)
    {
      if (link_socket_connection_oriented (c->c2.link_socket))
	{
	  if (c->c2.tls_multi->n_soft_errors)
	    check_tls_errors_co (c);
	}
      else
	{
	  if (c->c2.tls_multi->n_hard_errors)
	    check_tls_errors_nco (c);
	}
    }
#endif
}

/*
 * Check for possible incoming configuration
 * messages on the control channel.
 */
static inline void
check_incoming_control_channel (struct context *c)
{
#if P2MP
  void check_incoming_control_channel_dowork (struct context *c);
  if (tls_test_payload_len (c->c2.tls_multi) > 0)
    check_incoming_control_channel_dowork (c);
#endif
}

/*
 * Options like --up-delay need to be triggered by this function which
 * checks for connection establishment.
 */
static inline void
check_connection_established (struct context *c)
{
  void check_connection_established_dowork (struct context *c);
  if (event_timeout_defined (&c->c2.wait_for_connect))
    check_connection_established_dowork (c);
}

/*
 * Should we add routes?
 */
static inline void
check_add_routes (struct context *c)
{
  void check_add_routes_dowork (struct context *c);
  if (event_timeout_trigger (&c->c2.route_wakeup, &c->c2.timeval, ETT_DEFAULT))
    check_add_routes_dowork (c);
}

/*
 * Should we exit due to inactivity timeout?
 */
static inline void
check_inactivity_timeout (struct context *c)
{
  void check_inactivity_timeout_dowork (struct context *c);

  if (c->options.inactivity_timeout
      && event_timeout_trigger (&c->c2.inactivity_interval, &c->c2.timeval, ETT_DEFAULT))
    check_inactivity_timeout_dowork (c);
}

#if P2MP

static inline void
check_server_poll_timeout (struct context *c)
{
  void check_server_poll_timeout_dowork (struct context *c);

  if (c->options.server_poll_timeout
      && event_timeout_trigger (&c->c2.server_poll_interval, &c->c2.timeval, ETT_DEFAULT))
    check_server_poll_timeout_dowork (c);
}

/*
 * Scheduled exit?
 */
static inline void
check_scheduled_exit (struct context *c)
{
  void check_scheduled_exit_dowork (struct context *c);

  if (event_timeout_defined (&c->c2.scheduled_exit))
    {
      if (event_timeout_trigger (&c->c2.scheduled_exit, &c->c2.timeval, ETT_DEFAULT))
	check_scheduled_exit_dowork (c);
    }
}
#endif

/*
 * Should we write timer-triggered status file.
 */
static inline void
check_status_file (struct context *c)
{
  void check_status_file_dowork (struct context *c);

  if (c->c1.status_output)
    {
      if (status_trigger_tv (c->c1.status_output, &c->c2.timeval))
	check_status_file_dowork (c);
    }
}

#ifdef ENABLE_FRAGMENT
/*
 * Should we deliver a datagram fragment to remote?
 */
static inline void
check_fragment (struct context *c)
{
  void check_fragment_dowork (struct context *c);
  if (c->c2.fragment)
    check_fragment_dowork (c);
}
#endif

#if P2MP

/*
 * see if we should send a push_request in response to --pull
 */
static inline void
check_push_request (struct context *c)
{
  void check_push_request_dowork (struct context *c);
  if (event_timeout_trigger (&c->c2.push_request_interval, &c->c2.timeval, ETT_DEFAULT))
    check_push_request_dowork (c);
}

#endif

#ifdef USE_CRYPTO
/*
 * Should we persist our anti-replay packet ID state to disk?
 */
static inline void
check_packet_id_persist_flush (struct context *c)
{
  if (packet_id_persist_enabled (&c->c1.pid_persist)
      && event_timeout_trigger (&c->c2.packet_id_persist_interval, &c->c2.timeval, ETT_DEFAULT))
    packet_id_persist_save (&c->c1.pid_persist);
}
#endif

/*
 * Set our wakeup to 0 seconds, so we will be rescheduled
 * immediately.
 */
static inline void
context_immediate_reschedule (struct context *c)
{
  c->c2.timeval.tv_sec = 0;    /* ZERO-TIMEOUT */
  c->c2.timeval.tv_usec = 0;
}

static inline void
context_reschedule_sec (struct context *c, int sec)
{
  if (sec < 0)
    sec = 0;
  if (sec < c->c2.timeval.tv_sec)
    {
      c->c2.timeval.tv_sec = sec;
      c->c2.timeval.tv_usec = 0;
    }
}

static inline struct link_socket_info *
get_link_socket_info (struct context *c)
{
  if (c->c2.link_socket_info)
    return c->c2.link_socket_info;
  else
    return &c->c2.link_socket->info;
}

static inline void
register_activity (struct context *c, const int size)
{
  if (c->options.inactivity_timeout)
    {
      c->c2.inactivity_bytes += size;
      if (c->c2.inactivity_bytes >= c->options.inactivity_minimum_bytes)
	{
	  c->c2.inactivity_bytes = 0;
	  event_timeout_reset (&c->c2.inactivity_interval);
	}
    }
}

/*
 * Return the io_wait() flags appropriate for
 * a point-to-point tunnel.
 */
static inline unsigned int
p2p_iow_flags (const struct context *c)
{
  unsigned int flags = (IOW_SHAPER|IOW_CHECK_RESIDUAL|IOW_FRAG|IOW_READ|IOW_WAIT_SIGNAL);
  if (c->c2.to_link.len > 0)
    flags |= IOW_TO_LINK;
  if (c->c2.to_tun.len > 0)
    flags |= IOW_TO_TUN;
  return flags;
}

/*
 * This is the core I/O wait function, used for all I/O waits except
 * for TCP in server mode.
 */
static inline void
io_wait (struct context *c, const unsigned int flags)
{
  void io_wait_dowork (struct context *c, const unsigned int flags);

  if (c->c2.fast_io && (flags & (IOW_TO_TUN|IOW_TO_LINK|IOW_MBUF)))
    {
      /* fast path -- only for TUN/TAP/UDP writes */
      unsigned int ret = 0;
      if (flags & IOW_TO_TUN)
	ret |= TUN_WRITE;
      if (flags & (IOW_TO_LINK|IOW_MBUF))
	ret |= SOCKET_WRITE;
      c->c2.event_set_status = ret;
    }
  else
    {
      /* slow path */
      io_wait_dowork (c, flags);
    }
}

#define CONNECTION_ESTABLISHED(c) (get_link_socket_info(c)->connection_established)

#endif /* EVENT_INLINE_H */
