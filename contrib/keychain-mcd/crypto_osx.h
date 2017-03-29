/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2010 Brian Raderman <brian@irregularexpression.org>
 *  Copyright (C) 2013-2015 Vasily Kulikov <segoon@openwall.com>
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

#ifndef __crypto_osx_h__
#define __crypto_osx_h__

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

extern OSStatus SecKeyRawSign(
    SecKeyRef key,
    SecPadding padding,
    const uint8_t *dataToSign,
    size_t dataToSignLen,
    uint8_t *sig,
    size_t *sigLen
    );

void signData(SecIdentityRef identity, const uint8_t *from, int flen, uint8_t *to, size_t *tlen);

void printErrorMsg(const char *func, CFErrorRef error);

#endif /*__crypto_osx_h__ */
