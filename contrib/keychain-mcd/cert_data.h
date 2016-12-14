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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef __cert_data_h__
#define __cert_data_h__

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

typedef struct _CertData
{
    CFArrayRef subject;
    CFArrayRef issuer;
    CFStringRef serial;
    CFStringRef md5, sha1;
} CertData, *CertDataRef;

CertDataRef createCertDataFromCertificate(SecCertificateRef certificate);

CertDataRef createCertDataFromString(const char *description);

void destroyCertData(CertDataRef pCertData);

bool certDataMatchesTemplate(CertDataRef pCertData, CertDataRef pTemplate);

void printCertData(CertDataRef pCertData);

SecIdentityRef findIdentity(CertDataRef pCertDataTemplate);

#endif /* ifndef __cert_data_h__ */
