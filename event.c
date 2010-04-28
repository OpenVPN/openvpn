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

#include "buffer.h"
#include "error.h"
#include "integer.h"
#include "event.h"

#include "memdbg.h"

/*
 * Some OSes will prefer select() over poll()
 * when both are available.
 */
#if defined(TARGET_DARWIN)
#define SELECT_PREFERRED_OVER_POLL
#endif

/*
 * All non-windows OSes are assumed to have select()
 */
#ifdef WIN32
#define SELECT 0
#else
#define SELECT 1
#endif

/*
 * This should be set to the highest file descriptor
 * which can be used in one of the FD_ macros.
 */
#ifdef FD_SETSIZE
#define SELECT_MAX_FDS FD_SETSIZE
#else
#define SELECT_MAX_FDS 256
#endif

static inline int
tv_to_ms_timeout (const struct timeval *tv)
{
  if (tv->tv_sec == 0 && tv->tv_usec == 0)
    return 0;
  else
    return max_int (tv->tv_sec * 1000 + (tv->tv_usec + 500) / 1000, 1);
}

#ifdef WIN32

struct we_set
{
  struct event_set_functions func;
  bool fast;
  HANDLE *events;
  struct event_set_return *esr;
  int n_events;
  int capacity;
};

static inline void
we_set_event (struct we_set *wes, int i, event_t event, unsigned int rwflags, void *arg)
{
  ASSERT (i >= 0 && i < wes->capacity);

  if (rwflags == EVENT_READ)
    {
      ASSERT (event->read != NULL);
      wes->events[i] = event->read;
    }
  else if (rwflags == EVENT_WRITE)
    {
      ASSERT (event->write != NULL);
      wes->events[i] = event->write;
    }
  else
    msg (M_FATAL, "fatal error in we_set_events: rwflags=%d", rwflags);
      
  wes->esr[i].rwflags = rwflags;
  wes->esr[i].arg = arg;
}

static inline bool
we_append_event (struct we_set *wes, event_t event, unsigned int rwflags, void *arg)
{
  if (rwflags & EVENT_WRITE)
    {
      if (wes->n_events < wes->capacity)
	{
	  we_set_event (wes, wes->n_events, event, EVENT_WRITE, arg);
	  ++wes->n_events;
	}
      else
	return false;
    }
  if (rwflags & EVENT_READ)
    {
      if (wes->n_events < wes->capacity)
	{
	  we_set_event (wes, wes->n_events, event, EVENT_READ, arg);
	  ++wes->n_events;
	}
      else
	return false;
    }
  return true;
}

static void
we_del_event (struct we_set *wes, event_t event)
{
  int i, j = 0;
  const int len = wes->n_events;

  for (i = 0; i < len; ++i)
    {
      const HANDLE h = wes->events[i];
      if (h == event->read || h == event->write)
	--wes->n_events;
      else
	{
	  if (i != j)
	    {
	      wes->events[j] = wes->events[i];
	      wes->esr[j] = wes->esr[i];
	    }
	  ++j;
	}
    }
}

static void
we_del_index (struct we_set *wes, int index)
{
  int i;
  ASSERT (index >= 0 && index < wes->n_events);
  for (i = index; i < wes->n_events - 1; ++i)
    {
      wes->events[i] = wes->events[i+1];
      wes->esr[i] = wes->esr[i+1];
    }
  --wes->n_events;
}

static void
we_get_rw_indices (struct we_set *wes, event_t event, int *ri, int *wi)
{
  int i;
  *ri = *wi = -1;
  for (i = 0; i < wes->n_events; ++i)
    {
      const HANDLE h = wes->events[i];
      if (h == event->read)
	{
	  ASSERT (*ri == -1);
	  *ri = i;
	}
      else if (h == event->write)
	{
	  ASSERT (*wi == -1);
	  *wi = i;
	}
    }
}

static void
we_free (struct event_set *es)
{
  struct we_set *wes = (struct we_set *) es;
  free (wes->events);
  free (wes->esr);
  free (wes);
}

static void
we_reset (struct event_set *es)
{
  struct we_set *wes = (struct we_set *) es;
  ASSERT (wes->fast);
  wes->n_events = 0;
}

static void
we_del (struct event_set *es, event_t event)
{
  struct we_set *wes = (struct we_set *) es;
  ASSERT (!wes->fast);
  we_del_event (wes, event);
}

static void
we_ctl (struct event_set *es, event_t event, unsigned int rwflags, void *arg)
{
  struct we_set *wes = (struct we_set *) es;

  dmsg (D_EVENT_WAIT, "WE_CTL n=%d ev=0x%08x rwflags=0x%04x arg=" ptr_format,
       wes->n_events,
       (unsigned int)event,
       rwflags,
       (ptr_type)arg);

  if (wes->fast)
    {
      if (!we_append_event (wes, event, rwflags, arg))
	goto err;
    }
  else
    {
      int ri, wi;
      int one = -1;
      int n = 0;

      we_get_rw_indices (wes, event, &ri, &wi);
      if (wi >= 0)
	{
	  one = wi;
	  ++n;
	}
      if (ri >= 0)
	{
	  one = ri;
	  ++n;
	}
      switch (rwflags)
	{
	case 0:
	  switch (n)
	    {
	    case 0:
	      break;
	    case 1:
	      we_del_index (wes, one);
	      break;
	    case 2:
	      we_del_event (wes, event);
	      break;
	    default:
	      ASSERT (0);
	    }
	  break;
	case EVENT_READ:
	  switch (n)
	    {
	    case 0:
	      if (!we_append_event (wes, event, EVENT_READ, arg))
		goto err;
	      break;
	    case 1:
	      we_set_event (wes, one, event, EVENT_READ, arg);
	      break;
	    case 2:
	      we_del_index (wes, wi);
	      break;
	    default:
	      ASSERT (0);
	    }
	  break;
	case EVENT_WRITE:
	  switch (n)
	    {
	    case 0:
	      if (!we_append_event (wes, event, EVENT_WRITE, arg))
		goto err;
	      break;
	    case 1:
	      we_set_event (wes, one, event, EVENT_WRITE, arg);
	      break;
	    case 2:
	      we_del_index (wes, ri);
	      break;
	    default:
	      ASSERT (0);
	    }
	  break;
	case EVENT_READ|EVENT_WRITE:
	  switch (n)
	    {
	    case 0:
	      if (!we_append_event (wes, event, EVENT_READ|EVENT_WRITE, arg))
		goto err;
	      break;
	    case 1:
	      if (ri == -1)
		{
		  ASSERT (wi != -1);
		  if (!we_append_event (wes, event, EVENT_READ, arg))
		    goto err;
		}
	      else if (wi == -1)
		{
		  if (!we_append_event (wes, event, EVENT_WRITE, arg))
		    goto err;
		}
	      else
		ASSERT (0);
	      break;
	    case 2:
	      break;
	    default:
	      ASSERT (0);
	    }
	  break;
	default:
	  msg (M_FATAL, "fatal error in we_ctl: rwflags=%d", rwflags);
	}
    }
  return;

 err:
  msg (D_EVENT_ERRORS, "Error: Windows resource limit WSA_MAXIMUM_WAIT_EVENTS (%d) has been exceeded", WSA_MAXIMUM_WAIT_EVENTS);
}

static int
we_wait (struct event_set *es, const struct timeval *tv, struct event_set_return *out, int outlen)
{
  struct we_set *wes = (struct we_set *) es;
  const int timeout = tv_to_ms_timeout (tv);
  DWORD status;

  dmsg (D_EVENT_WAIT, "WE_WAIT enter n=%d to=%d", wes->n_events, timeout);

#ifdef ENABLE_DEBUG
  if (check_debug_level (D_EVENT_WAIT)) {
    int i;
    for (i = 0; i < wes->n_events; ++i)
      dmsg (D_EVENT_WAIT, "[%d] ev=0x%08x rwflags=0x%04x arg=" ptr_format,
       i,
       (unsigned int)wes->events[i],
       wes->esr[i].rwflags,
       (ptr_type)wes->esr[i].arg);
  }
#endif

  /*
   * First poll our event list with 0 timeout
   */
  status = WSAWaitForMultipleEvents(
    (DWORD) wes->n_events,
    wes->events,
    FALSE,
    (DWORD) 0,
    FALSE);

  /*
   * If at least one event is already set, we must
   * individually poll the whole list.
   */
  if (status >= WSA_WAIT_EVENT_0 && status < WSA_WAIT_EVENT_0 + (DWORD) wes->n_events)
    {
      int i;
      int j = 0;
      for (i = 0; i < wes->n_events; ++i)
	{
	  if (j >= outlen)
	    break;
	  if (WaitForSingleObject (wes->events[i], 0) == WAIT_OBJECT_0)
	    {
	      *out = wes->esr[i];
	      dmsg (D_EVENT_WAIT, "WE_WAIT leave [%d,%d] rwflags=0x%04x arg=" ptr_format,
		   i, j, out->rwflags, (ptr_type)out->arg);
	      ++j;
	      ++out;
	    }
	}
      return j;
    }
  else
    {
      /*
       * If caller specified timeout > 0, we know at this point
       * that no events are set, so wait only for the first event
       * (or timeout) and return at most one event_set_return object.
       *
       * If caller specified timeout == 0, the second call to
       * WSAWaitForMultipleEvents would be redundant -- just
       * return 0 indicating timeout.
       */
      if (timeout > 0)
	status = WSAWaitForMultipleEvents(
	  (DWORD) wes->n_events,
	  wes->events,
	  FALSE,
	  (DWORD) timeout,
	  FALSE);
  
      if (outlen >= 1 && status >= WSA_WAIT_EVENT_0 && status < WSA_WAIT_EVENT_0 + (DWORD) wes->n_events)
	{
	  *out = wes->esr[status - WSA_WAIT_EVENT_0];
	  dmsg (D_EVENT_WAIT, "WE_WAIT leave rwflags=0x%04x arg=" ptr_format,
	       out->rwflags, (ptr_type)out->arg);
	  return 1;
	}
      else if (status == WSA_WAIT_TIMEOUT)
	return 0;
      else
	return -1;
    }
}

static struct event_set *
we_init (int *maxevents, unsigned int flags)
{
  struct we_set *wes;

  dmsg (D_EVENT_WAIT, "WE_INIT maxevents=%d flags=0x%08x", *maxevents, flags);

  ALLOC_OBJ_CLEAR (wes, struct we_set);

  /* set dispatch functions */
  wes->func.free = we_free;
  wes->func.reset = we_reset;
  wes->func.del = we_del;
  wes->func.ctl = we_ctl;
  wes->func.wait = we_wait;

  if (flags & EVENT_METHOD_FAST)
    wes->fast = true;
  wes->n_events = 0;

  /* Figure our event capacity */
  ASSERT (*maxevents > 0);
  wes->capacity = min_int (*maxevents * 2, WSA_MAXIMUM_WAIT_EVENTS);
  *maxevents = min_int (*maxevents, WSA_MAXIMUM_WAIT_EVENTS);

  /* Allocate space for Win32 event handles */
  ALLOC_ARRAY_CLEAR (wes->events, HANDLE, wes->capacity);

  /* Allocate space for event_set_return objects */
  ALLOC_ARRAY_CLEAR (wes->esr, struct event_set_return, wes->capacity);

  dmsg (D_EVENT_WAIT, "WE_INIT maxevents=%d capacity=%d",
       *maxevents, wes->capacity);

  return (struct event_set *) wes;
}

#endif /* WIN32 */

#if EPOLL

struct ep_set
{
  struct event_set_functions func;
  bool fast;
  int epfd;
  int maxevents;
  struct epoll_event *events;
};

static void
ep_free (struct event_set *es)
{
  struct ep_set *eps = (struct ep_set *) es;
  close (eps->epfd);
  free (eps->events);
  free (eps);
}

static void
ep_reset (struct event_set *es)
{
  const struct ep_set *eps = (struct ep_set *) es;
  ASSERT (eps->fast);
}

static void
ep_del (struct event_set *es, event_t event)
{
  struct epoll_event ev;
  struct ep_set *eps = (struct ep_set *) es;

  dmsg (D_EVENT_WAIT, "EP_DEL ev=%d", (int)event);

  ASSERT (!eps->fast);
  CLEAR (ev);
  epoll_ctl (eps->epfd, EPOLL_CTL_DEL, event, &ev);
}

static void
ep_ctl (struct event_set *es, event_t event, unsigned int rwflags, void *arg)
{
  struct ep_set *eps = (struct ep_set *) es;
  struct epoll_event ev;

  CLEAR (ev);

  ev.data.ptr = arg;
  if (rwflags & EVENT_READ)
    ev.events |= EPOLLIN;
  if (rwflags & EVENT_WRITE)
    ev.events |= EPOLLOUT;

  dmsg (D_EVENT_WAIT, "EP_CTL fd=%d rwflags=0x%04x ev=0x%08x arg=" ptr_format,
       (int)event,
       rwflags,
       (unsigned int)ev.events,
       (ptr_type)ev.data.ptr);

  if (epoll_ctl (eps->epfd, EPOLL_CTL_MOD, event, &ev) < 0)
    {
      if (errno == ENOENT)
	{
	  if (epoll_ctl (eps->epfd, EPOLL_CTL_ADD, event, &ev) < 0)
	    msg (M_ERR, "EVENT: epoll_ctl EPOLL_CTL_ADD failed");
	}
      else
	msg (M_ERR, "EVENT: epoll_ctl EPOLL_CTL_MOD failed");
    }
}

static int
ep_wait (struct event_set *es, const struct timeval *tv, struct event_set_return *out, int outlen)
{
  struct ep_set *eps = (struct ep_set *) es;
  int stat;

  if (outlen > eps->maxevents)
    outlen = eps->maxevents;

  stat = epoll_wait (eps->epfd, eps->events, outlen, tv_to_ms_timeout (tv));
  ASSERT (stat <= outlen);

  if (stat > 0)
    {
      int i;
      const struct epoll_event *ev = eps->events;
      struct event_set_return *esr = out;
      for (i = 0; i < stat; ++i)
	{
	  esr->rwflags = 0;
	  if (ev->events & (EPOLLIN|EPOLLPRI|EPOLLERR|EPOLLHUP))
	    esr->rwflags |= EVENT_READ;
	  if (ev->events & EPOLLOUT)
	    esr->rwflags |= EVENT_WRITE;
	  esr->arg = ev->data.ptr;
	  dmsg (D_EVENT_WAIT, "EP_WAIT[%d] rwflags=0x%04x ev=0x%08x arg=" ptr_format,
	       i, esr->rwflags, ev->events, (ptr_type)ev->data.ptr);
	  ++ev;
	  ++esr;
	}
    }
  return stat;
}

static struct event_set *
ep_init (int *maxevents, unsigned int flags)
{
  struct ep_set *eps;
  int fd;

  dmsg (D_EVENT_WAIT, "EP_INIT maxevents=%d flags=0x%08x", *maxevents, flags);

  /* open epoll file descriptor */
  fd = epoll_create (*maxevents);
  if (fd < 0)
    return NULL;

  ALLOC_OBJ_CLEAR (eps, struct ep_set);

  /* set dispatch functions */
  eps->func.free = ep_free;
  eps->func.reset = ep_reset;
  eps->func.del = ep_del;
  eps->func.ctl = ep_ctl;
  eps->func.wait = ep_wait;

  /* fast method ("sort of") corresponds to epoll one-shot */
  if (flags & EVENT_METHOD_FAST)
    eps->fast = true;

  /* allocate space for epoll_wait return */
  ASSERT (*maxevents > 0);
  eps->maxevents = *maxevents;
  ALLOC_ARRAY_CLEAR (eps->events, struct epoll_event, eps->maxevents);

  /* set epoll control fd */
  eps->epfd = fd;

  return (struct event_set *) eps;
}
#endif /* EPOLL */

#if POLL

struct po_set
{
  struct event_set_functions func;
  bool fast;
  struct pollfd *events;
  void **args;
  int n_events;
  int capacity;
};

static void
po_free (struct event_set *es)
{
  struct po_set *pos = (struct po_set *) es;
  free (pos->events);
  free (pos->args);
  free (pos);
}

static void
po_reset (struct event_set *es)
{
  struct po_set *pos = (struct po_set *) es;
  ASSERT (pos->fast);
  pos->n_events = 0;
}

static void
po_del (struct event_set *es, event_t event)
{
  struct po_set *pos = (struct po_set *) es;
  int i;

  dmsg (D_EVENT_WAIT, "PO_DEL ev=%d", (int)event);

  ASSERT (!pos->fast);
  for (i = 0; i < pos->n_events; ++i)
    {
      if (pos->events[i].fd == event)
	{
	  int j;
	  for (j = i; j < pos->n_events - 1; ++j)
	    {
	      pos->events[j] = pos->events[j+1];
	      pos->args[j] = pos->args[j+1];
	    }
	  --pos->n_events;
	  break;
	}
    }
}

static inline void
po_set_pollfd_events (struct pollfd *pfdp, unsigned int rwflags)
{
  pfdp->events = 0;
  if (rwflags & EVENT_WRITE)
    pfdp->events |= POLLOUT;
  if (rwflags & EVENT_READ)
    pfdp->events |= (POLLIN|POLLPRI);
}

static inline bool
po_append_event (struct po_set *pos, event_t event, unsigned int rwflags, void *arg)
{
  if (pos->n_events < pos->capacity)
    {
      struct pollfd *pfdp = &pos->events[pos->n_events];
      pfdp->fd = event;
      pos->args[pos->n_events] = arg;
      po_set_pollfd_events (pfdp, rwflags);
      ++pos->n_events;
      return true;
    }
  else
    return false;
}

static void
po_ctl (struct event_set *es, event_t event, unsigned int rwflags, void *arg)
{
  struct po_set *pos = (struct po_set *) es;

  dmsg (D_EVENT_WAIT, "PO_CTL rwflags=0x%04x ev=%d arg=" ptr_format,
       rwflags, (int)event, (ptr_type)arg);

  if (pos->fast)
    {
      if (!po_append_event (pos, event, rwflags, arg))
	goto err;
    }
  else
    {
      int i;
      for (i = 0; i < pos->n_events; ++i)
	{
	  struct pollfd *pfdp = &pos->events[i];
	  if (pfdp->fd == event)
	    {
	      pos->args[i] = arg;
	      po_set_pollfd_events (pfdp, rwflags);
	      goto done;
	    }
	}
      if (!po_append_event (pos, event, rwflags, arg))
	goto err;
    }

 done:
  return;

 err:
  msg (D_EVENT_ERRORS, "Error: poll: too many I/O wait events");
}

static int
po_wait (struct event_set *es, const struct timeval *tv, struct event_set_return *out, int outlen)
{
  struct po_set *pos = (struct po_set *) es;
  int stat;

  stat = poll (pos->events, pos->n_events, tv_to_ms_timeout (tv));

  ASSERT (stat <= pos->n_events);

  if (stat > 0)
    {
      int i, j=0;
      const struct pollfd *pfdp = pos->events;
      for (i = 0; i < pos->n_events && j < outlen; ++i)
	{
	  if (pfdp->revents & (POLLIN|POLLPRI|POLLERR|POLLHUP|POLLOUT))
	    {
	      out->rwflags = 0;
	      if (pfdp->revents & (POLLIN|POLLPRI|POLLERR|POLLHUP))
		out->rwflags |= EVENT_READ;
	      if (pfdp->revents & POLLOUT)
		out->rwflags |= EVENT_WRITE;
	      out->arg = pos->args[i];
	      dmsg (D_EVENT_WAIT, "PO_WAIT[%d,%d] fd=%d rev=0x%08x rwflags=0x%04x arg=" ptr_format " %s",
		   i, j, pfdp->fd, pfdp->revents, out->rwflags, (ptr_type)out->arg, pos->fast ? "" : "[scalable]");
	      ++out;
	      ++j;
	    }
	  else if (pfdp->revents)
	    {
	      msg (D_EVENT_ERRORS, "Error: poll: unknown revents=0x%04x", (unsigned int)pfdp->revents);
	    }
	  ++pfdp;
	}
      return j;
    }
  return stat;
}

static struct event_set *
po_init (int *maxevents, unsigned int flags)
{
  struct po_set *pos;

  dmsg (D_EVENT_WAIT, "PO_INIT maxevents=%d flags=0x%08x", *maxevents, flags);

  ALLOC_OBJ_CLEAR (pos, struct po_set);

  /* set dispatch functions */
  pos->func.free = po_free;
  pos->func.reset = po_reset;
  pos->func.del = po_del;
  pos->func.ctl = po_ctl;
  pos->func.wait = po_wait;

  if (flags & EVENT_METHOD_FAST)
    pos->fast = true;

  pos->n_events = 0;

  /* Figure our event capacity */
  ASSERT (*maxevents > 0);
  pos->capacity = *maxevents;

  /* Allocate space for pollfd structures to be passed to poll() */
  ALLOC_ARRAY_CLEAR (pos->events, struct pollfd, pos->capacity);

  /* Allocate space for event_set_return objects */
  ALLOC_ARRAY_CLEAR (pos->args, void *, pos->capacity);

  return (struct event_set *) pos;
}
#endif /* POLL */

#if SELECT

struct se_set
{
  struct event_set_functions func;
  bool fast;
  fd_set readfds;
  fd_set writefds;
  void **args;  /* allocated to capacity size */
  int maxfd;    /* largest fd seen so far, always < capacity */
  int capacity; /* fixed largest fd + 1 */
};

static void
se_free (struct event_set *es)
{
  struct se_set *ses = (struct se_set *) es;
  free (ses->args);
  free (ses);
}

static void
se_reset (struct event_set *es)
{
  struct se_set *ses = (struct se_set *) es;
  int i;
  ASSERT (ses->fast);
  
  dmsg (D_EVENT_WAIT, "SE_RESET");

  FD_ZERO (&ses->readfds);
  FD_ZERO (&ses->writefds);
  for (i = 0; i <= ses->maxfd; ++i)
    ses->args[i] = NULL;
  ses->maxfd = -1;
}

static void
se_del (struct event_set *es, event_t event)
{
  struct se_set *ses = (struct se_set *) es;
  ASSERT (!ses->fast);

  dmsg (D_EVENT_WAIT, "SE_DEL ev=%d", (int)event);

  if (event >= 0 && event < ses->capacity)
    {
      FD_CLR (event, &ses->readfds);
      FD_CLR (event, &ses->writefds);
      ses->args[event] = NULL;
    }
  else
    msg (D_EVENT_ERRORS, "Error: select/se_del: too many I/O wait events");
  return;
}

static void
se_ctl (struct event_set *es, event_t event, unsigned int rwflags, void *arg)
{
  struct se_set *ses = (struct se_set *) es;

  dmsg (D_EVENT_WAIT, "SE_CTL rwflags=0x%04x ev=%d fast=%d cap=%d maxfd=%d arg=" ptr_format,
       rwflags, (int)event, (int)ses->fast, ses->capacity, ses->maxfd, (ptr_type)arg);

  if (event >= 0 && event < ses->capacity)
    {
      ses->maxfd = max_int (event, ses->maxfd);
      ses->args[event] = arg;
      if (ses->fast)
	{
	  if (rwflags & EVENT_READ)
	    FD_SET (event, &ses->readfds);
	  if (rwflags & EVENT_WRITE)
	    FD_SET (event, &ses->writefds);
	}
      else
	{
	  if (rwflags & EVENT_READ)
	    FD_SET (event, &ses->readfds);
	  else
	    FD_CLR (event, &ses->readfds);
	  if (rwflags & EVENT_WRITE)
	    FD_SET (event, &ses->writefds);
	  else
	    FD_CLR (event, &ses->writefds);
	}
    }
  else
    {
      msg (D_EVENT_ERRORS, "Error: select: too many I/O wait events, fd=%d cap=%d",
	   (int) event,
	   ses->capacity);
    }
}

static int
se_wait_return (struct se_set *ses,
		fd_set *read,
		fd_set *write,
		struct event_set_return *out,
		int outlen)
{
  int i, j = 0;
  for (i = 0; i <= ses->maxfd && j < outlen; ++i)
    {
      const bool r = FD_ISSET (i, read);
      const bool w = FD_ISSET (i, write);
      if (r || w)
	{
	  out->rwflags = 0;
	  if (r)
	    out->rwflags |= EVENT_READ;
	  if (w)
	    out->rwflags |= EVENT_WRITE;
	  out->arg = ses->args[i];
	  dmsg (D_EVENT_WAIT, "SE_WAIT[%d,%d] rwflags=0x%04x arg=" ptr_format,
	       i, j, out->rwflags, (ptr_type)out->arg);
	  ++out;
	  ++j;
	}
    }
  return j;
}

static int
se_wait_fast (struct event_set *es, const struct timeval *tv, struct event_set_return *out, int outlen)
{
  struct se_set *ses = (struct se_set *) es;
  struct timeval tv_tmp = *tv;
  int stat;

  dmsg (D_EVENT_WAIT, "SE_WAIT_FAST maxfd=%d tv=%d/%d",
	ses->maxfd,
	(int)tv_tmp.tv_sec,
	(int)tv_tmp.tv_usec);

  stat = select (ses->maxfd + 1, &ses->readfds, &ses->writefds, NULL, &tv_tmp);

  if (stat > 0)
    stat = se_wait_return (ses, &ses->readfds, &ses->writefds, out, outlen);

  return stat;
}

static int
se_wait_scalable (struct event_set *es, const struct timeval *tv, struct event_set_return *out, int outlen)
{
  struct se_set *ses = (struct se_set *) es;
  struct timeval tv_tmp = *tv;
  fd_set read = ses->readfds;
  fd_set write = ses->writefds;
  int stat;

  dmsg (D_EVENT_WAIT, "SE_WAIT_SCALEABLE maxfd=%d tv=%d/%d",
	ses->maxfd, (int)tv_tmp.tv_sec, (int)tv_tmp.tv_usec);

  stat = select (ses->maxfd + 1, &read, &write, NULL, &tv_tmp);

  if (stat > 0)
    stat = se_wait_return (ses, &read, &write, out, outlen);

  return stat;
}

static struct event_set *
se_init (int *maxevents, unsigned int flags)
{
  struct se_set *ses;

  dmsg (D_EVENT_WAIT, "SE_INIT maxevents=%d flags=0x%08x", *maxevents, flags);

  ALLOC_OBJ_CLEAR (ses, struct se_set);

  /* set dispatch functions */
  ses->func.free = se_free;
  ses->func.reset = se_reset;
  ses->func.del = se_del;
  ses->func.ctl = se_ctl;
  ses->func.wait = se_wait_scalable;

  if (flags & EVENT_METHOD_FAST)
    {
      ses->fast = true;
      ses->func.wait = se_wait_fast;
    }

  /* Select needs to be passed this value + 1 */
  ses->maxfd = -1;

  /* Set our event capacity */
  ASSERT (*maxevents > 0);
  *maxevents = min_int (*maxevents, SELECT_MAX_FDS);
  ses->capacity = SELECT_MAX_FDS;

  /* Allocate space for event_set_return void * args */
  ALLOC_ARRAY_CLEAR (ses->args, void *, ses->capacity);

  return (struct event_set *) ses;
}
#endif /* SELECT */

static struct event_set *
event_set_init_simple (int *maxevents, unsigned int flags)
{
  struct event_set *ret = NULL;
#ifdef WIN32
  ret = we_init (maxevents, flags);
#elif POLL && SELECT
#if 0 /* Define to 1 if EVENT_METHOD_US_TIMEOUT should cause select to be favored over poll */
  if (flags & EVENT_METHOD_US_TIMEOUT)
    ret = se_init (maxevents, flags); 
#endif
# ifdef SELECT_PREFERRED_OVER_POLL
   if (!ret)
     ret = se_init (maxevents, flags);
   if (!ret)
     ret = po_init (maxevents, flags);
# else
   if (!ret)
     ret = po_init (maxevents, flags);
   if (!ret)
     ret = se_init (maxevents, flags);
# endif
#elif POLL
  ret = po_init (maxevents, flags);
#elif SELECT
  ret = se_init (maxevents, flags);
#else
#error At least one of poll, select, or WSAWaitForMultipleEvents must be supported by the kernel
#endif
  ASSERT (ret);
  return ret;
}

static struct event_set *
event_set_init_scalable (int *maxevents, unsigned int flags)
{
  struct event_set *ret = NULL;
#if EPOLL
  ret = ep_init (maxevents, flags);
  if (!ret)
    {
      msg (M_WARN, "Note: sys_epoll API is unavailable, falling back to poll/select API");
      ret = event_set_init_simple (maxevents, flags);
    }
#else
  ret = event_set_init_simple (maxevents, flags);
#endif
  ASSERT (ret);
  return ret;
}

struct event_set *
event_set_init (int *maxevents, unsigned int flags)
{
  if (flags & EVENT_METHOD_FAST)
    return event_set_init_simple (maxevents, flags);
  else
    return event_set_init_scalable (maxevents, flags);
}
