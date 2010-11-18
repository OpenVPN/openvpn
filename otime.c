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

#include "otime.h"

#include "memdbg.h"

time_t now = 0;            /* GLOBAL */

#if TIME_BACKTRACK_PROTECTION && defined(HAVE_GETTIMEOFDAY)

static time_t now_adj = 0; /* GLOBAL */
time_t now_usec = 0;       /* GLOBAL */

/*
 * Try to filter out time instability caused by the system
 * clock backtracking or jumping forward.
 */

void
update_now (const time_t system_time)
{
  const int forward_threshold = 86400; /* threshold at which to dampen forward jumps */
  const int backward_trigger  = 10;    /* backward jump must be >= this many seconds before we adjust */
  time_t real_time = system_time + now_adj;

  if (real_time > now)
    {
      const time_t overshoot = real_time - now - 1;
      if (overshoot > forward_threshold && now_adj >= overshoot)
        {
          now_adj -= overshoot;
          real_time -= overshoot;
        }
      now = real_time;
    }
  else if (real_time < now - backward_trigger)
    now_adj += (now - real_time);
}

void
update_now_usec (struct timeval *tv)
{
  const time_t last = now;
  update_now (tv->tv_sec);
  if (now > last || (now == last && tv->tv_usec > now_usec))
    now_usec = tv->tv_usec;
}

#endif /* TIME_BACKTRACK_PROTECTION && defined(HAVE_GETTIMEOFDAY) */

/* 
 * Return a numerical string describing a struct timeval.
 */
const char *
tv_string (const struct timeval *tv, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (64, gc);
  buf_printf (&out, "[%d/%d]",
	      (int) tv->tv_sec,
	      (int )tv->tv_usec);
  return BSTR (&out);
}

/* 
 * Return an ascii string describing an absolute
 * date/time in a struct timeval.
 * 
 */
const char *
tv_string_abs (const struct timeval *tv, struct gc_arena *gc)
{
  return time_string ((time_t) tv->tv_sec,
		      (int) tv->tv_usec,
		      true,
		      gc);
}

/* format a time_t as ascii, or use current time if 0 */

const char *
time_string (time_t t, int usec, bool show_usec, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (64, gc);
  struct timeval tv;

  if (t)
    {
      tv.tv_sec = t;
      tv.tv_usec = usec;
    }
  else
    {
#ifdef HAVE_GETTIMEOFDAY
      if (gettimeofday (&tv, NULL))
#endif
	{
	  tv.tv_sec = time (NULL);
	  tv.tv_usec = 0;
	}
    }

  t = tv.tv_sec;
  buf_printf (&out, "%s", ctime(&t));
  buf_rmtail (&out, '\n');

  if (show_usec && tv.tv_usec)
    buf_printf (&out, " us=%d", (int)tv.tv_usec);

  return BSTR (&out);
}

/*
 * Limit the frequency of an event stream.
 *
 * Used to control maximum rate of new
 * incoming connections.
 */

struct frequency_limit *
frequency_limit_init (int max, int per)
{
  struct frequency_limit *f;

  ASSERT (max >= 0 && per >= 0);

  ALLOC_OBJ (f, struct frequency_limit);
  f->max = max;
  f->per = per;
  f->n = 0;
  f->reset = 0;
  return f;
}

void
frequency_limit_free (struct frequency_limit *f)
{
  free (f);
}

bool
frequency_limit_event_allowed (struct frequency_limit *f)
{
  if (f->per)
    {
      bool ret;
      if (now >= f->reset + f->per)
	{
	  f->reset = now;
	  f->n = 0;
	}
      ret = (++f->n <= f->max);
      return ret;
    }
  else
    return true;
}

#ifdef WIN32

static time_t gtc_base = 0;
static DWORD gtc_last = 0;
static time_t last_sec = 0;
static unsigned int last_msec = 0;
static bool bt_last = false;

static void
gettimeofday_calibrate (void)
{
  const time_t t = time(NULL);
  const DWORD gtc = GetTickCount();
  gtc_base = t - gtc/1000;
  gtc_last = gtc;
}

/*
 * Rewritten by JY for OpenVPN 2.1, after I realized that
 * QueryPerformanceCounter takes nearly 2 orders of magnitude
 * more processor cycles than GetTickCount.
 */
int
gettimeofday (struct timeval *tv, void *tz)
{
  const DWORD gtc = GetTickCount();
  bool bt = false;
  time_t sec;
  unsigned int msec;
  const int backtrack_hold_seconds = 10;

  /* recalibrate at the dreaded 49.7 day mark */
  if (!gtc_base || gtc < gtc_last)
    gettimeofday_calibrate ();
  gtc_last = gtc;

  sec = gtc_base + gtc / 1000;
  msec = gtc % 1000;

  if (sec == last_sec)
    {
      if (msec < last_msec)
	{
	  msec = last_msec;
	  bt = true;
	}
    }
  else if (sec < last_sec)
    {
      /* We try to dampen out backtracks of less than backtrack_hold_seconds.
	 Larger backtracks will be passed through and dealt with by the
	 TIME_BACKTRACK_PROTECTION code (if enabled) */
      if (sec > last_sec - backtrack_hold_seconds)
	{
	  sec = last_sec;
	  msec = last_msec;
	}
      bt = true;
    }

  tv->tv_sec = last_sec = sec;
  tv->tv_usec = (last_msec = msec) * 1000;

  if (bt && !bt_last)
    gettimeofday_calibrate ();
  bt_last = bt;

  return 0;
}

#endif /* WIN32 */

#ifdef TIME_TEST
void
time_test (void)
{
  struct timeval tv;
  time_t t;
  int i;
  for (i = 0; i < 10000; ++i)
    {
      t = time(NULL);
      gettimeofday (&tv, NULL);
#if 1
      msg (M_INFO, "t=%u s=%u us=%u",
	       (unsigned int)t,
	       (unsigned int)tv.tv_sec,
	       (unsigned int)tv.tv_usec);
#endif
    }
}
#endif
