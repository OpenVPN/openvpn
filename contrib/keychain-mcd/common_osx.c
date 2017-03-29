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

/*
 #include "config.h"
 #include "syshead.h"
 #include "common.h"
 #include "buffer.h"
 #include "error.h"
 */

#include "common_osx.h"
#include <err.h>

void
printCFString(CFStringRef str)
{
    CFIndex bufferLength = CFStringGetLength(str) + 1;
    char *pBuffer = (char *)malloc(sizeof(char) * bufferLength);
    CFStringGetCString(str, pBuffer, bufferLength, kCFStringEncodingUTF8);
    warnx("%s\n", pBuffer);
    free(pBuffer);
}

char *
cfstringToCstr(CFStringRef str)
{
    CFIndex bufferLength = CFStringGetLength(str) + 1;
    char *pBuffer = (char *)malloc(sizeof(char) * bufferLength);
    CFStringGetCString(str, pBuffer, bufferLength, kCFStringEncodingUTF8);
    return pBuffer;
}

void
appendHexChar(CFMutableStringRef str, unsigned char halfByte)
{
    if (halfByte < 10)
    {
        CFStringAppendFormat(str, NULL, CFSTR("%d"), halfByte);
    }
    else
    {
        char tmp[2] = {'A'+halfByte-10, 0};
        CFStringAppendCString(str, tmp, kCFStringEncodingUTF8);
    }
}

CFStringRef
createHexString(unsigned char *pData, int length)
{
    unsigned char byte, low, high;
    int i;
    CFMutableStringRef str = CFStringCreateMutable(NULL, 0);

    for (i = 0; i < length; i++)
    {
        byte = pData[i];
        low = byte & 0x0F;
        high = (byte >> 4);

        appendHexChar(str, high);
        appendHexChar(str, low);

        if (i != (length - 1))
        {
            CFStringAppendCString(str, " ", kCFStringEncodingUTF8);
        }
    }

    return str;
}

void
printHex(unsigned char *pData, int length)
{
    CFStringRef hexStr = createHexString(pData, length);
    printCFString(hexStr);
    CFRelease(hexStr);
}
