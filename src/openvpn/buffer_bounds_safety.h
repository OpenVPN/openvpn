/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2026 Jeff Bindel <jeff@incrediblybased.co>
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

/**
 * @file
 * @brief Portability macros for optional Clang -fbounds-safety.
 *
 * When OVPN_SUPPORT_FBOUNDS_SAFETY is defined (typically via
 * -DOVPN_SUPPORT_FBOUNDS_SAFETY and a Clang toolchain that implements
 * -fbounds-safety), these macros expand to Clang bounds annotations.
 * Otherwise they expand to nothing so default builds are unchanged.
 *
 * Pattern matches libwebp / libpng / giflib / lz4 / zstd / libzip
 * inert-macro -fbounds-safety adoption: annotations are inert unless
 * explicitly enabled.
 */

#ifndef BUFFER_BOUNDS_SAFETY_H
#define BUFFER_BOUNDS_SAFETY_H

#ifdef OVPN_SUPPORT_FBOUNDS_SAFETY

#  include <ptrcheck.h>
/* Non-ABI-breaking sized-by annotations for byte buffers whose companion
 * field / argument is a capacity in bytes (e.g. buffer.capacity).
 * Prefer OVPN_SIZED_BY for buffers that are non-NULL when live; use
 * *_OR_NULL when the pointer may be NULL while the companion capacity
 * is zero (struct buffer.data may be NULL after buf_reset / CLEAR).
 */
#  define OVPN_SIZED_BY(n) __sized_by(n)
#  define OVPN_SIZED_BY_OR_NULL(n) __sized_by_or_null(n)
#  define OVPN_COUNTED_BY(n) __counted_by(n)
#  define OVPN_COUNTED_BY_OR_NULL(n) __counted_by_or_null(n)

#else /* !OVPN_SUPPORT_FBOUNDS_SAFETY */

#  define OVPN_SIZED_BY(n)
#  define OVPN_SIZED_BY_OR_NULL(n)
#  define OVPN_COUNTED_BY(n)
#  define OVPN_COUNTED_BY_OR_NULL(n)

#endif /* OVPN_SUPPORT_FBOUNDS_SAFETY */

#endif /* BUFFER_BOUNDS_SAFETY_H */
