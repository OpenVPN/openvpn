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

#ifndef __PKCS11_HELPER_CONFIG_H
#define __PKCS11_HELPER_CONFIG_H

#if!defined(PKCS11H_NO_NEED_INCLUDE_CONFIG)

#if defined(WIN32)
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#endif /* PKCS11H_NO_NEED_INCLUDE_CONFIG */

#ifdef ENABLE_PKCS11
#define PKCS11H_ENABLE_HELPER
#endif

#ifdef PKCS11H_ENABLE_HELPER

#if defined(WIN32)
#include "cryptoki-win32.h"
#else
#include "cryptoki.h"
#endif

#include "error.h"
#include "misc.h"
#include "ssl.h"

#define PKCS11ASSERT		ASSERT
#define PKCS11LOG		msg
#define PKCS11DLOG		dmsg
#define PKCS11_LOG_DEBUG2	D_PKCS11_DEBUG
#define PKCS11_LOG_DEBUG1	D_SHOW_PKCS11
#define PKCS11_LOG_INFO		M_INFO
#define PKCS11_LOG_WARN		M_WARN
#define PKCS11_LOG_ERROR	M_FATAL

#if !defined(false)
#define false 0
#endif
#if !defined(true)
#define true (!false)
#endif

#if !defined(IN)
#define IN
#endif
#if !defined(OUT)
#define OUT
#endif

#define PKCS11_PRM_SLOT_TYPE	"--pkcs11-slot-type"
#define PKCS11_PRM_SLOT_ID	"--pkcs11-slot"
#define PKCS11_PRM_OBJ_TYPE	"--pkcs11-id-type"
#define PKCS11_PRM_OBJ_ID	"--pkcs11-id"

#endif		/* PKCS11H_ENABLE_HELPER */
#endif		/* __PKCS11_HELPER_CONFIG_H */
