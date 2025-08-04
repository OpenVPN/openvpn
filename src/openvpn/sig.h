/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef SIG_H
#define SIG_H

#include "status.h"
#include "win32.h"

#define SIG_SOURCE_SOFT 0
#define SIG_SOURCE_HARD 1
/* CONNECTION_FAILED is also a "soft" status,
 * It is thrown if a connection attempt fails
 */
#define SIG_SOURCE_CONNECTION_FAILED 2

/*
 * Signal information, including signal code
 * and descriptive text.
 */
struct signal_info
{
    volatile int signal_received;
    volatile int source;
    const char *signal_text;
};

#define IS_SIG(c) ((c)->sig->signal_received)

struct context;

extern struct signal_info siginfo_static;

int parse_signal(const char *signame);

const char *signal_name(const int sig, const bool upper);

const char *signal_description(const int signum, const char *sigtext);

void throw_signal(const int signum);

void throw_signal_soft(const int signum, const char *signal_text);

void pre_init_signal_catch(void);

void post_init_signal_catch(void);

void restore_signal_state(void);

void print_signal(const struct signal_info *si, const char *title, int msglevel);

void print_status(struct context *c, struct status_output *so);

void remap_signal(struct context *c);

void signal_restart_status(const struct signal_info *si);

bool process_signal(struct context *c);

void register_signal(struct signal_info *si, int sig, const char *text);

void process_explicit_exit_notification_timer_wakeup(struct context *c);

/**
 * Clear the signal if its current value equals signum. If signum is
 * zero the signal is cleared independent of its current value.
 * @returns the current value of the signal.
 */
int signal_reset(struct signal_info *si, int signum);

static inline void
halt_non_edge_triggered_signals(void)
{
#ifdef _WIN32
    win32_signal_close(&win32_signal);
#endif
}

/**
 * Copy the global signal_received (if non-zero) to the passed-in argument sig.
 * As the former is volatile, do not assign if sig and &signal_received are the
 * same.  Even on windows signal_received is really volatile as it can change if
 * a ctrl-C or ctrl-break is delivered. So use the same logic as above.
 *
 * Also, on windows always call win32_signal_get to pickup any signals simulated by
 * key-board short cuts or the exit event.
 */

static inline void
get_signal(volatile int *sig)
{
#ifdef _WIN32
    const int i = win32_signal_get(&win32_signal);
#else
    const int i = siginfo_static.signal_received;
#endif
    if (i && sig != &siginfo_static.signal_received)
    {
        *sig = i;
    }
}

#endif /* ifndef SIG_H */
