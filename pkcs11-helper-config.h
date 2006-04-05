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

#ifndef __PKCS11H_HELPER_CONFIG_H
#define __PKCS11H_HELPER_CONFIG_H

#if !defined(PKCS11H_NO_NEED_INCLUDE_CONFIG)

#if defined(WIN32)
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#endif /* PKCS11H_NO_NEED_INCLUDE_CONFIG */

#ifdef ENABLE_PKCS11
#define ENABLE_PKCS11H_HELPER
#endif

#ifdef ENABLE_PKCS11H_HELPER

#include "error.h"
#include "misc.h"
#include "ssl.h"

#undef PKCS11H_USE_CYGWIN	/* cygwin is not supported in openvpn */

#if !defined(FALSE)
#define FALSE false
#endif
#if !defined(TRUE)
#define TRUE true
#endif

typedef bool PKCS11H_BOOL;

#if !defined(IN)
#define IN
#endif
#if !defined(OUT)
#define OUT
#endif

#ifdef ENABLE_DEBUG
#define ENABLE_PKCS11H_DEBUG
#endif
#ifdef USE_PTHREAD
#define ENABLE_PKCS11H_THREADING
#endif
#undef  ENABLE_PKCS11H_TOKEN
#undef  ENABLE_PKCS11H_DATA
#define ENABLE_PKCS11H_CERTIFICATE
#define ENABLE_PKCS11H_LOCATE
#undef  ENABLE_PKCS11H_ENUM
#undef  ENABLE_PKCS11H_SLOTEVENT
#define ENABLE_PKCS11H_OPENSSL
#define ENABLE_PKCS11H_STANDALONE

#define PKCS11H_PRM_SLOT_TYPE	"--pkcs11-slot-type"
#define PKCS11H_PRM_SLOT_ID	"--pkcs11-slot"
#define PKCS11H_PRM_OBJ_TYPE	"--pkcs11-id-type"
#define PKCS11H_PRM_OBJ_ID	"--pkcs11-id"

#define PKCS11H_ASSERT		ASSERT
#define PKCS11H_TIME		openvpn_time

#if defined(WIN32) || defined(PKCS11H_USE_CYGWIN)
#include "cryptoki-win32.h"
#else
#include "cryptoki.h"
#endif

#endif		/* PKCS11_ENABLE_HELPER */
#endif		/* __PKCS11H_HELPER_CONFIG_H */
