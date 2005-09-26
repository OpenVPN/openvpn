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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "otime.h"

#include "memdbg.h"

volatile time_t now; /* GLOBAL */

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

  mutex_lock_static (L_CTIME);
  buf_printf (&out, "%s", ctime ((const time_t *)&tv.tv_sec));
  mutex_unlock_static (L_CTIME);
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

static double counterPerMicrosecond = -1.0;            /* GLOBAL */
static unsigned __int64 frequency = 0;                 /* GLOBAL */
static unsigned __int64 timeSecOffset = 0;             /* GLOBAL */
static unsigned __int64 startPerformanceCounter = 0;   /* GLOBAL */

/*
 * gettimeofday for windows
 *
 * CounterPerMicrosecond is the number of counts per microsecond.
 * Double is required if we have less than 1 counter per microsecond.  This has not been tested.
 * On a PIII 700, I get about 3.579545.  This is guaranteed not to change while the processor is running.
 * We really don't need to check for loop detection.  On my machine it would take about 59645564 days to loop.
 * (2^64) / frequency / 60 / 60 / 24.
 *
 */
int
gettimeofday(struct timeval *tv, void *tz)
{
  unsigned __int64 counter;

  QueryPerformanceCounter((LARGE_INTEGER *) &counter);

  if (counter < startPerformanceCounter || counterPerMicrosecond == -1.0)
    {
      time_t t;
      mutex_lock (L_GETTIMEOFDAY);

      QueryPerformanceFrequency((LARGE_INTEGER *) &frequency);

      counterPerMicrosecond = (double) ((__int64) frequency) / 1000000.0f;

      time(&t);
      QueryPerformanceCounter((LARGE_INTEGER *) &counter);
      startPerformanceCounter = counter;

      counter /= frequency;

      timeSecOffset = t - counter;

      mutex_unlock (L_GETTIMEOFDAY);
      QueryPerformanceCounter((LARGE_INTEGER *) &counter);
    }

  tv->tv_sec = (counter / frequency) + timeSecOffset;
  tv->tv_usec = ((__int64) (((__int64) counter) / counterPerMicrosecond) % 1000000);

  return 0;
}

#endif /* WIN32 */
