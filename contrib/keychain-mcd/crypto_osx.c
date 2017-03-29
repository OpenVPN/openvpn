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


#include <CommonCrypto/CommonDigest.h>
#include <Security/SecKey.h>
#include <Security/Security.h>

#include "crypto_osx.h"
#include <err.h>

void
printErrorMsg(const char *func, CFErrorRef error)
{
    CFStringRef desc = CFErrorCopyDescription(error);
    warnx("%s failed: %s", func, CFStringGetCStringPtr(desc, kCFStringEncodingUTF8));
    CFRelease(desc);
}

void
printErrorStatusMsg(const char *func, OSStatus status)
{
    CFStringRef error;
    error = SecCopyErrorMessageString(status, NULL);
    if (error)
    {
        warnx("%s failed: %s", func, CFStringGetCStringPtr(error, kCFStringEncodingUTF8));
        CFRelease(error);
    }
    else
    {
        warnx("%s failed: %X", func, (int)status);
    }
}

void
signData(SecIdentityRef identity, const uint8_t *from, int flen, uint8_t *to, size_t *tlen)
{
    SecKeyRef privateKey = NULL;
    OSStatus status;

    status = SecIdentityCopyPrivateKey(identity,  &privateKey);
    if (status != noErr)
    {
        printErrorStatusMsg("signData: SecIdentityCopyPrivateKey", status);
        *tlen = 0;
        return;
    }

    status = SecKeyRawSign(privateKey, kSecPaddingPKCS1, from, flen, to, tlen);
    CFRelease(privateKey);
    if (status != noErr)
    {
        printErrorStatusMsg("signData: SecKeyRawSign", status);
        *tlen = 0;
        return;
    }
}
