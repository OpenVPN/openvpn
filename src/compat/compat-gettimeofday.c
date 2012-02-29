/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

#ifndef HAVE_GETTIMEOFDAY

#include "compat.h"

#ifdef WIN32
/*
 * NOTICE: mingw has much faster gettimeofday!
 * autoconf will set HAVE_GETTIMEOFDAY
 */

#include <windows.h>
#include <time.h>

static time_t gtc_base = 0;
static DWORD gtc_last = 0;
static time_t last_sec = 0;
static unsigned int last_msec = 0;
static int bt_last = 0;

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
  int bt = 0;
  time_t sec;
  unsigned int msec;
  const int backtrack_hold_seconds = 10;

  (void)tz;

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
	  bt = 1;
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
      bt = 1;
    }

  tv->tv_sec = (long)last_sec = (long)sec;
  tv->tv_usec = (last_msec = msec) * 1000;

  if (bt && !bt_last)
    gettimeofday_calibrate ();
  bt_last = bt;

  return 0;
}

#else

#ifdef HAVE_TIME_H
#include <time.h>
#endif

int
gettimeofday (struct timeval *tv, void *tz)
{
	(void)tz;
	tv->tv_sec = time(NULL);
	tv->tv_usec = 0;
	return 0;
}

#endif /* WIN32 */

#endif /* HAVE_GETTIMEOFDAY */
