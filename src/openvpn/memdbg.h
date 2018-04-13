/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
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

#ifndef MEMDBG_H
#define MEMDBG_H

/*
 * Valgrind debugging support.
 *
 * Valgrind is a great tool for debugging memory issues,
 * though it seems to generate a lot of warnings in OpenSSL
 * about uninitialized data. To silence these warnings,
 * I've put together a suppressions file
 * in debug/valgrind-suppress.
 *
 * Also, grep for VALGRIND_MAKE_READABLE in the OpenVPN source.
 * Because valgrind thinks that some of the data passed from
 * OpenSSL back to OpenVPN is tainted due to being sourced
 * from uninitialized data, we need to untaint it before use --
 * otherwise we will get a lot of useless warnings.
 *
 *   valgrind --tool=memcheck --error-limit=no --suppressions=debug/valgrind-suppress --gen-suppressions=yes ./openvpn ...
 */

#ifdef USE_VALGRIND

#include <valgrind/memcheck.h>

#define VALGRIND_MAKE_READABLE(addr, len)

#else  /* ifdef USE_VALGRIND */

#define VALGRIND_MAKE_READABLE(addr, len)

#endif

#ifdef DMALLOC /* see ./configure options to enable */

/*
 * See ./configure options to enable dmalloc
 * support for memory leak checking.
 *
 * The dmalloc package can be downloaded from:
 *
 *     http://dmalloc.com/
 *
 * When dmalloc is installed and enabled,
 * use this command prior to running openvpn:
 *
 *    dmalloc -l dlog -i 100 low -p log-unknown
 *
 * Also, put this in your .bashrc file:
 *
 *    function dmalloc { eval `command dmalloc -b $*`; }
 *
 * Or take a more low-level approach:
 *
 *    export DMALLOC_OPTIONS="debug=0x4e48503,inter=100,log=dlog"
 *
 *  NOTE: When building dmalloc you need to add something
 *  like this to dmalloc's settings.h -- it will allocate a static
 *  buffer to be used as the malloc arena:
 *
 *  #define INTERNAL_MEMORY_SPACE (1024 * 1024 * 50)
 */

#include <dmalloc.h>

#define openvpn_dmalloc(file, line, size) dmalloc_malloc((file), (line), (size), DMALLOC_FUNC_MALLOC, 0, 0)

/*
 * This #define will put the line number of the log
 * file position where leaked memory was allocated instead
 * of the source code file and line number.  Make sure
 * to increase the size of dmalloc's info tables,
 * (MEMORY_TABLE_SIZE in settings.h)
 * otherwise it might get overwhelmed by the large
 * number of unique file/line combinations.
 */
#if 0
#undef malloc
#define malloc(size) openvpn_dmalloc("logfile", x_msg_line_num, (size))
#endif

#endif /* DMALLOC */

/*
 * Force buffers to be zeroed after allocation.
 * For debugging only.
 */
/*#define ZERO_BUFFER_ON_ALLOC*/

#endif /* MEMDBG_H */
