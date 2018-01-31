/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2010-2018 Fox Crypto B.V. <openvpn@fox-it.com>
 *
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

/**
 * @file
 * Memory management strategies documentation file.
 */

/**
 * @page memory_management OpenVPN's memory management strategies
 *
 * This section describes several implementation details relating to
 * OpenVPN's memory management strategies.
 *
 * During operation, the OpenVPN process performs all kinds of operations
 * on blocks of data.  Receiving packets, encrypting content, prepending
 * headers, etc.  To make the programmer's job easier and to decrease the
 * likelihood of memory-related bugs, OpenVPN uses its own memory %buffer
 * library and garbage collection facilities.  These are described in
 * brief here.
 *
 * @section memory_management_buffer The buffer structure
 *
 * The \c buffer structure is a wrapper around a block of dynamically
 * allocated memory which keeps track of the block's capacity \c
 * buffer.capacity and location in memory \c buffer.data.  This structure
 * supports efficient prepending and appending within the allocated memory
 * through the use of offset \c buffer.offset and length \c buffer.len
 * fields.  See the \c buffer documentation for more details on the
 * structure itself.
 *
 * OpenVPN's %buffer library, implemented in the \c buffer.h and \c
 * buffer.c files, contains many utility functions for working with \c
 * buffer structures.  These functions facilitate common operations, such
 * as allocating, freeing, reading and writing to \c buffer structures,
 * and even offer several more advanced operations, such as string
 * matching and creating sub-buffers.
 *
 * Not only do these utility functions make working with \c buffer
 * structures easy, they also perform extensive error checking.  Each
 * function, where necessary, checks whether enough space is available
 * before performing its actions.  This minimizes the chance of bugs
 * leading to %buffer overflows and other vulnerabilities.
 *
 * @section memory_management_frame The frame structure
 *
 * The \c frame structure keeps track of the maximum allowed packet
 * geometries of a network connection.
 *
 * It is used, for example, to determine the size of \c buffer structures
 * in which to store data channel packets.  This is done by having each
 * data channel processing module register the maximum amount of extra
 * space it will need for header prepending and content expansion in the
 * \c frame structure. Once these parameters are known, \c buffer
 * structures can be allocated, based on the \c frame parameters, so that
 * they are large enough to allow efficient prepending of headers and
 * processing of content.
 *
 * @section memory_management_garbage Garbage collection
 *
 * OpenVPN has many sizable functions which perform various actions
 * depending on their %context.  This makes it difficult to know in advance
 * exactly how much memory must be allocated.  The garbage collection
 * facilities are used to keep track of dynamic allocations, thereby
 * allowing easy collective freeing of the allocated memory.
 *
 * The garbage collection system is implemented by the \c gc_arena and \c
 * gc_entry structures.  The arena represents a garbage collecting unit,
 * and contains a linked list of entries.  Each entry represents one block
 * of dynamically allocated memory.
 *
 * The garbage collection system also contains various utility functions
 * for working with the garbage collection structures.  These include
 * functions for initializing new arenas, allocating memory of a given
 * size and registering the allocation in an arena, and freeing all the
 * allocated memory associated with an arena.
 */
