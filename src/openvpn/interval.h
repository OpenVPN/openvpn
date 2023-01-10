/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * The interval_ routines are designed to optimize the calling of a routine
 * (normally tls_multi_process()) which can be called less frequently
 * between triggers.
 */

#ifndef INTERVAL_H
#define INTERVAL_H

#include "otime.h"

#define INTERVAL_DEBUG 0

/*
 * Designed to limit calls to expensive functions that need to be called
 * regularly.
 */

struct interval
{
    interval_t refresh;
    interval_t horizon;
    time_t future_trigger;
    time_t last_action;
    time_t last_test_true;
};

void interval_init(struct interval *top, int horizon, int refresh);

/*
 * IF
 *   last_action less than horizon seconds ago
 *   OR last_test_true more than refresh seconds ago
 *   OR hit future_trigger
 * THEN
 *   return true
 * ELSE
 *   set wakeup to the number of seconds until a true return
 *   return false
 */

static inline bool
interval_test(struct interval *top)
{
    bool trigger = false;
    const time_t local_now = now;

    if (top->future_trigger && local_now >= top->future_trigger)
    {
        trigger = true;
        top->future_trigger = 0;
    }

    if (top->last_action + top->horizon > local_now
        || top->last_test_true + top->refresh <= local_now
        || trigger)
    {
        top->last_test_true = local_now;
#if INTERVAL_DEBUG
        dmsg(D_INTERVAL, "INTERVAL interval_test true");
#endif
        return true;
    }
    else
    {
        return false;
    }
}

static inline void
interval_schedule_wakeup(struct interval *top, interval_t *wakeup)
{
    const time_t local_now = now;
    interval_earliest_wakeup(wakeup, top->last_test_true + top->refresh, local_now);
    interval_earliest_wakeup(wakeup, top->future_trigger, local_now);
#if INTERVAL_DEBUG
    dmsg(D_INTERVAL, "INTERVAL interval_schedule wakeup=%d", (int)*wakeup);
#endif
}

/*
 * In wakeup seconds, interval_test will return true once.
 */
static inline void
interval_future_trigger(struct interval *top, interval_t wakeup)
{
    if (wakeup)
    {
#if INTERVAL_DEBUG
        dmsg(D_INTERVAL, "INTERVAL interval_future_trigger %d", (int)wakeup);
#endif
        top->future_trigger = now + wakeup;
    }
}

/*
 * Once an action is triggered, interval_test will remain true for
 * horizon seconds.
 */
static inline void
interval_action(struct interval *top)
{
#if INTERVAL_DEBUG
    dmsg(D_INTERVAL, "INTERVAL action");
#endif
    top->last_action = now;
}

/*
 * Measure when n seconds beyond an event have elapsed
 */

struct event_timeout
{
    bool defined;       /**< This timeout is active */
    interval_t n;       /**< periodic interval for periodic timeouts */
    time_t last;        /**< time of last event */
};

static inline bool
event_timeout_defined(const struct event_timeout *et)
{
    return et->defined;
}
/**
 * Clears the timeout and reset all values to 0. Following timer checks will
 * not trigger.
 *
 * @param et    timer struct
 */
static inline void
event_timeout_clear(struct event_timeout *et)
{
    et->defined = false;
    et->n = 0;
    et->last = 0;
}


/**
 * Initialises a timer struct. The timer will become true/trigger after
 * last + n seconds.
 *
 *
 * @param et            Timer struct
 * @param n             Interval of the timer for periodic timer. A negative
 *                      value for n will be interpreted as 0.
 * @param last          Sets the base time of the timer.
 */
static inline void
event_timeout_init(struct event_timeout *et, interval_t n, const time_t last)
{
    et->defined = true;
    et->n = (n >= 0) ? n : 0;
    et->last = last;
}

/**
 * Resets a timer.
 *
 * Sets the last time the timer has been triggered for the calculation of the
 * next event.
 * @param et
 */
static inline void
event_timeout_reset(struct event_timeout *et)
{
    if (et->defined)
    {
        et->last = now;
    }
}

/**
 * Sets the interval n of a timeout.
 * @param et
 * @param n Interval value of the timer, negative values
 *          will be interpreted as 0
 *
 * @note you might need to call reset_coarse_timers after this
 */
static inline void
event_timeout_modify_wakeup(struct event_timeout *et, interval_t n)
{
    if (et->defined)
    {
        et->n = (n >= 0) ? n : 0;
    }
}

/**
 * Returns the time until the timeout should triggered, from \c now.
 * This function does not check if the timeout is actually valid.
 */
static inline interval_t
event_timeout_remaining(struct event_timeout *et)
{
    return (interval_t) ((et->last + et->n) - now);
}

#define ETT_DEFAULT (-1)

/**
 * This is the principal function for testing and triggering recurring
 * timers.
 *
 * If *et is not triggered, *tv is set to remaining time until the timeout if
 * not already lower:
 *
 *      *tv = minimum(*tv, event_timeout_remaining(*et))
 *
 * If *et triggers and et_const_retry is negative (ETT_DEFAULT is -1):
 *  - the function will return true
 *  - *et will be armed for the next event (et->last set to now).
 *  - *tv will be lowered to the event period (n) if larger than the
 *     period of the event (set to *et's next timeout)
 *  - *et will not changed (ie also not rearmed, stays armed)
 *
 * If *et triggers and et_const_retry >= 0, *tv will be lowered to et_const_try
 * if larger:
 *
 *    *tv = *minimum(*tv, et_const_retry)
 *
 * This is mainly useful if the trigger cannot yet be triggered for other
 * reasons and a backoff timeout should be returned if the timer is ready
 * to trigger.
 *
 *
 * @param et                the timeout to check
 * @param tv                will be set to timeout for next check for this
 *                          timeout unless already smaller.
 * @param et_const_retry    see above
 * @return                  if the timeout has triggered and event has been reset
 */
bool event_timeout_trigger(struct event_timeout *et,
                           struct timeval *tv,
                           int et_const_retry);

/*
 * Measure time intervals in microseconds
 */

#define USEC_TIMER_MAX      60 /* maximum interval size in seconds */

#define USEC_TIMER_MAX_USEC (USEC_TIMER_MAX * 1000000)

struct usec_timer {
    struct timeval start;
    struct timeval end;
};

#ifdef HAVE_GETTIMEOFDAY

static inline void
usec_timer_start(struct usec_timer *obj)
{
    CLEAR(*obj);
    openvpn_gettimeofday(&obj->start, NULL);
}

static inline void
usec_timer_end(struct usec_timer *obj)
{
    openvpn_gettimeofday(&obj->end, NULL);
}

#endif /* HAVE_GETTIMEOFDAY */

static inline bool
usec_timer_interval_defined(struct usec_timer *obj)
{
    return obj->start.tv_sec && obj->end.tv_sec;
}

static inline int
usec_timer_interval(struct usec_timer *obj)
{
    return tv_subtract(&obj->end, &obj->start, USEC_TIMER_MAX);
}

#endif /* INTERVAL_H */
