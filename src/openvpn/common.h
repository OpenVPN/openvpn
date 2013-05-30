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

#ifndef COMMON_H
#define COMMON_H

/*
 * Statistics counters and associated printf formats.
 */
#ifdef USE_64_BIT_COUNTERS
  typedef unsigned long long int counter_type;
# ifdef WIN32
#  define counter_format  "%I64u"
# else
#  define counter_format  "%llu"
# endif
#else
  typedef unsigned int counter_type;
# define counter_format   "%u"
#endif

/*
 * Time intervals
 */
typedef int interval_t;

/*
 * Used as an upper bound for timeouts.
 */
#define BIG_TIMEOUT  (60*60*24*7)  /* one week (in seconds) */

/*
 * Printf formats for special types
 */
#ifdef _WIN64
#define ptr_format              "0x%I64x"
#else
#define ptr_format              "0x%08lx"
#endif
#define time_format             "%lu"
#define fragment_header_format  "0x%08x"

/* these are used to cast the arguments
 * and MUST match the formats above */
typedef unsigned long time_type;
#ifdef _WIN64
typedef unsigned long long ptr_type;
#else
typedef unsigned long ptr_type;
#endif

/* the --client-config-dir default file */
#define CCD_DEFAULT "DEFAULT"

/*
 * This parameter controls the TLS channel buffer size and the
 * maximum size of a single TLS message (cleartext).
 * This parameter must be >= PUSH_BUNDLE_SIZE
 */
#define TLS_CHANNEL_BUF_SIZE 2048

/*
 * This parameter controls the maximum size of a bundle
 * of pushed options.
 */
#define PUSH_BUNDLE_SIZE 1024

/*
 * In how many seconds does client re-send PUSH_REQUEST if we haven't yet received a reply
 */
#define PUSH_REQUEST_INTERVAL 5

/*
 * A sort of pseudo-filename for data provided inline within
 * the configuration file.
 */
#define INLINE_FILE_TAG "[[INLINE]]"

/*
 * Script security warning
 */
#define SCRIPT_SECURITY_WARNING "WARNING: External program may not be called unless '--script-security 2' or higher is enabled. See --help text or man page for detailed info."

#endif
