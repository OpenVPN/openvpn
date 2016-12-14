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


#include "cert_data.h"
#include <CommonCrypto/CommonDigest.h>
#include <openssl/ssl.h>

#include "common_osx.h"
#include "crypto_osx.h"
#include <err.h>

CFStringRef kCertDataSubjectName = CFSTR("subject"),
            kCertDataIssuerName = CFSTR("issuer"),
            kCertDataSha1Name = CFSTR("SHA1"),
            kCertDataMd5Name = CFSTR("MD5"),
            kCertDataSerialName = CFSTR("serial"),
            kCertNameFwdSlash = CFSTR("/"),
            kCertNameEquals = CFSTR("=");
CFStringRef kCertNameOrganization = CFSTR("o"),
            kCertNameOrganizationalUnit = CFSTR("ou"),
            kCertNameCountry = CFSTR("c"),
            kCertNameLocality = CFSTR("l"),
            kCertNameState = CFSTR("st"),
            kCertNameCommonName = CFSTR("cn"),
            kCertNameEmail = CFSTR("e");
CFStringRef kStringSpace = CFSTR(" "),
            kStringEmpty = CFSTR("");

typedef struct _CertName
{
    CFArrayRef countryName, organization, organizationalUnit, commonName, description, emailAddress,
               stateName, localityName;
} CertName, *CertNameRef;

typedef struct _DescData
{
    CFStringRef name, value;
} DescData, *DescDataRef;

void destroyDescData(DescDataRef pData);

CertNameRef
createCertName()
{
    CertNameRef pCertName = (CertNameRef)malloc(sizeof(CertName));
    pCertName->countryName = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    pCertName->organization =  CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    pCertName->organizationalUnit = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    pCertName->commonName = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    pCertName->description = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    pCertName->emailAddress = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    pCertName->stateName = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    pCertName->localityName = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    return pCertName;
}

void
destroyCertName(CertNameRef pCertName)
{
    if (!pCertName)
    {
        return;
    }

    CFRelease(pCertName->countryName);
    CFRelease(pCertName->organization);
    CFRelease(pCertName->organizationalUnit);
    CFRelease(pCertName->commonName);
    CFRelease(pCertName->description);
    CFRelease(pCertName->emailAddress);
    CFRelease(pCertName->stateName);
    CFRelease(pCertName->localityName);
    free(pCertName);
}

bool
CFStringRefCmpCString(CFStringRef cfstr, const char *str)
{
    CFStringRef tmp = CFStringCreateWithCStringNoCopy(NULL, str, kCFStringEncodingUTF8, kCFAllocatorNull);
    CFComparisonResult cresult = CFStringCompare(cfstr, tmp, 0);
    bool result = cresult == kCFCompareEqualTo;
    CFRelease(tmp);
    return result;
}

CFDateRef
GetDateFieldFromCertificate(SecCertificateRef certificate, CFTypeRef oid)
{
    const void *keys[] = { oid };
    CFDictionaryRef dict = NULL;
    CFErrorRef error;
    CFDateRef date = NULL;

    CFArrayRef keySelection = CFArrayCreate(NULL, keys, sizeof(keys)/sizeof(keys[0]), &kCFTypeArrayCallBacks);
    dict = SecCertificateCopyValues(certificate, keySelection, &error);
    if (dict == NULL)
    {
        printErrorMsg("GetDateFieldFromCertificate: SecCertificateCopyValues", error);
        goto release_ks;
    }
    CFDictionaryRef vals = dict ? CFDictionaryGetValue(dict, oid) : NULL;
    CFNumberRef vals2 = vals ? CFDictionaryGetValue(vals, kSecPropertyKeyValue) : NULL;
    if (vals2 == NULL)
    {
        goto release_dict;
    }

    CFAbsoluteTime validityNotBefore;
    if (CFNumberGetValue(vals2, kCFNumberDoubleType, &validityNotBefore))
    {
        date = CFDateCreate(kCFAllocatorDefault,validityNotBefore);
    }

release_dict:
    CFRelease(dict);
release_ks:
    CFRelease(keySelection);
    return date;
}

CFArrayRef
GetFieldsFromCertificate(SecCertificateRef certificate, CFTypeRef oid)
{
    CFMutableArrayRef fields = CFArrayCreateMutable(NULL, 0, NULL);
    CertNameRef pCertName = createCertName();
    const void *keys[] = { oid, };
    CFDictionaryRef dict;
    CFErrorRef error;

    CFArrayRef keySelection = CFArrayCreate(NULL, keys, 1, NULL);

    dict = SecCertificateCopyValues(certificate, keySelection, &error);
    if (dict == NULL)
    {
        printErrorMsg("GetFieldsFromCertificate: SecCertificateCopyValues", error);
        CFRelease(keySelection);
        CFRelease(fields);
        destroyCertName(pCertName);
        return NULL;
    }
    CFDictionaryRef vals = CFDictionaryGetValue(dict, oid);
    CFArrayRef vals2 = vals ? CFDictionaryGetValue(vals, kSecPropertyKeyValue) : NULL;
    if (vals2)
    {
        for (int i = 0; i < CFArrayGetCount(vals2); i++) {
            CFDictionaryRef subDict = CFArrayGetValueAtIndex(vals2, i);
            CFStringRef label = CFDictionaryGetValue(subDict, kSecPropertyKeyLabel);
            CFStringRef value = CFDictionaryGetValue(subDict, kSecPropertyKeyValue);

            if (CFStringCompare(label, kSecOIDEmailAddress, 0) == kCFCompareEqualTo)
            {
                CFArrayAppendValue((CFMutableArrayRef)pCertName->emailAddress, value);
            }
            else if (CFStringCompare(label, kSecOIDCountryName, 0) == kCFCompareEqualTo)
            {
                CFArrayAppendValue((CFMutableArrayRef)pCertName->countryName, value);
            }
            else if (CFStringCompare(label, kSecOIDOrganizationName, 0) == kCFCompareEqualTo)
            {
                CFArrayAppendValue((CFMutableArrayRef)pCertName->organization, value);
            }
            else if (CFStringCompare(label, kSecOIDOrganizationalUnitName, 0) == kCFCompareEqualTo)
            {
                CFArrayAppendValue((CFMutableArrayRef)pCertName->organizationalUnit, value);
            }
            else if (CFStringCompare(label, kSecOIDCommonName, 0) == kCFCompareEqualTo)
            {
                CFArrayAppendValue((CFMutableArrayRef)pCertName->commonName, value);
            }
            else if (CFStringCompare(label, kSecOIDDescription, 0) == kCFCompareEqualTo)
            {
                CFArrayAppendValue((CFMutableArrayRef)pCertName->description, value);
            }
            else if (CFStringCompare(label, kSecOIDStateProvinceName, 0) == kCFCompareEqualTo)
            {
                CFArrayAppendValue((CFMutableArrayRef)pCertName->stateName, value);
            }
            else if (CFStringCompare(label, kSecOIDLocalityName, 0) == kCFCompareEqualTo)
            {
                CFArrayAppendValue((CFMutableArrayRef)pCertName->localityName, value);
            }
        }
        CFArrayAppendValue(fields, pCertName);
    }

    CFRelease(dict);
    CFRelease(keySelection);
    return fields;
}

CertDataRef
createCertDataFromCertificate(SecCertificateRef certificate)
{
    CertDataRef pCertData = (CertDataRef)malloc(sizeof(CertData));
    pCertData->subject = GetFieldsFromCertificate(certificate, kSecOIDX509V1SubjectName);
    pCertData->issuer = GetFieldsFromCertificate(certificate, kSecOIDX509V1IssuerName);

    CFDataRef data = SecCertificateCopyData(certificate);
    if (data == NULL)
    {
        warnx("SecCertificateCopyData() returned NULL");
        destroyCertData(pCertData);
        return NULL;
    }

    unsigned char sha1[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(CFDataGetBytePtr(data), CFDataGetLength(data), sha1);
    pCertData->sha1 = createHexString(sha1, CC_SHA1_DIGEST_LENGTH);

    unsigned char md5[CC_MD5_DIGEST_LENGTH];
    CC_MD5(CFDataGetBytePtr(data), CFDataGetLength(data), md5);
    pCertData->md5 = createHexString((unsigned char *)md5, CC_MD5_DIGEST_LENGTH);

    CFDataRef serial = SecCertificateCopySerialNumber(certificate, NULL);
    pCertData->serial = createHexString((unsigned char *)CFDataGetBytePtr(serial), CFDataGetLength(serial));
    CFRelease(serial);

    return pCertData;
}

CFStringRef
stringFromRange(const char *cstring, CFRange range)
{
    CFStringRef str = CFStringCreateWithBytes(NULL, (uint8 *)&cstring[range.location], range.length, kCFStringEncodingUTF8, false);
    CFMutableStringRef mutableStr = CFStringCreateMutableCopy(NULL, 0, str);
    CFStringTrimWhitespace(mutableStr);
    CFRelease(str);
    return mutableStr;
}

DescDataRef
createDescData(const char *description, CFRange nameRange, CFRange valueRange)
{
    DescDataRef pRetVal = (DescDataRef)malloc(sizeof(DescData));

    memset(pRetVal, 0, sizeof(DescData));

    if (nameRange.length > 0)
    {
        pRetVal->name = stringFromRange(description, nameRange);
    }

    if (valueRange.length > 0)
    {
        pRetVal->value = stringFromRange(description, valueRange);
    }

#if 0
    fprintf(stderr, "name = '%s', value = '%s'\n",
            CFStringGetCStringPtr(pRetVal->name, kCFStringEncodingUTF8),
            CFStringGetCStringPtr(pRetVal->value, kCFStringEncodingUTF8));
#endif
    return pRetVal;
}

void
destroyDescData(DescDataRef pData)
{
    if (pData->name)
    {
        CFRelease(pData->name);
    }

    if (pData->value)
    {
        CFRelease(pData->value);
    }

    free(pData);
}

CFArrayRef
createDescDataPairs(const char *description)
{
    int numChars = strlen(description);
    CFRange nameRange, valueRange;
    DescDataRef pData;
    CFMutableArrayRef retVal = CFArrayCreateMutable(NULL, 0, NULL);

    int i = 0;

    nameRange = CFRangeMake(0, 0);
    valueRange = CFRangeMake(0, 0);
    bool bInValue = false;

    while (i < numChars)
    {
        if (!bInValue && (description[i] != ':'))
        {
            nameRange.length++;
        }
        else if (bInValue && (description[i] != ':'))
        {
            valueRange.length++;
        }
        else if (!bInValue)
        {
            bInValue = true;
            valueRange.location = i + 1;
            valueRange.length = 0;
        }
        else /*(bInValue) */
        {
            bInValue = false;
            while (description[i] != ' ')
            {
                valueRange.length--;
                i--;
            }

            pData = createDescData(description, nameRange, valueRange);
            CFArrayAppendValue(retVal, pData);

            nameRange.location = i + 1;
            nameRange.length = 0;
        }

        i++;
    }

    pData = createDescData(description, nameRange, valueRange);
    CFArrayAppendValue(retVal, pData);
    return retVal;
}

void
arrayDestroyDescData(const void *val, void *context)
{
    DescDataRef pData = (DescDataRef) val;
    destroyDescData(pData);
}


int
parseNameComponent(CFStringRef dn, CFStringRef *pName, CFStringRef *pValue)
{
    CFArrayRef nameStrings = CFStringCreateArrayBySeparatingStrings(NULL, dn, kCertNameEquals);

    *pName = *pValue = NULL;

    if (CFArrayGetCount(nameStrings) != 2)
    {
        return 0;
    }

    CFMutableStringRef str;

    str = CFStringCreateMutableCopy(NULL, 0, CFArrayGetValueAtIndex(nameStrings, 0));
    CFStringTrimWhitespace(str);
    *pName = str;

    str = CFStringCreateMutableCopy(NULL, 0, CFArrayGetValueAtIndex(nameStrings, 1));
    CFStringTrimWhitespace(str);
    *pValue = str;

    CFRelease(nameStrings);
    return 1;
}

int
tryAppendSingleCertField(CertNameRef pCertName, CFArrayRef where, CFStringRef key,
                         CFStringRef name, CFStringRef value)
{
    if (CFStringCompareWithOptions(name, key, CFRangeMake(0, CFStringGetLength(name)), kCFCompareCaseInsensitive)
        == kCFCompareEqualTo)
    {
        CFArrayAppendValue((CFMutableArrayRef)where, value);
        return 1;
    }
    return 0;
}

int
appendCertField(CertNameRef pCert, CFStringRef name, CFStringRef value)
{
    struct {
        CFArrayRef field;
        CFStringRef key;
    } fields[] = {
        { pCert->organization, kCertNameOrganization},
        { pCert->organizationalUnit, kCertNameOrganizationalUnit},
        { pCert->countryName, kCertNameCountry},
        { pCert->localityName, kCertNameLocality},
        { pCert->stateName, kCertNameState},
        { pCert->commonName, kCertNameCommonName},
        { pCert->emailAddress, kCertNameEmail},
    };
    int i;
    int ret = 0;

    for (i = 0; i<sizeof(fields)/sizeof(fields[0]); i++)
        ret += tryAppendSingleCertField(pCert, fields[i].field, fields[i].key, name, value);
    return ret;
}

int
parseCertName(CFStringRef nameDesc, CFMutableArrayRef names)
{
    CFArrayRef nameStrings = CFStringCreateArrayBySeparatingStrings(NULL, nameDesc, kCertNameFwdSlash);
    int count = CFArrayGetCount(nameStrings);
    int i;
    int ret = 1;

    CertNameRef pCertName = createCertName();

    for (i = 0; i < count; i++)
    {
        CFMutableStringRef dn = CFStringCreateMutableCopy(NULL, 0, CFArrayGetValueAtIndex(nameStrings, i));
        CFStringTrimWhitespace(dn);

        CFStringRef name, value;

        if (!parseNameComponent(dn, &name, &value))
        {
            ret = 0;
        }

        if (!name || !value)
        {
            if (name)
            {
                CFRelease(name);
            }

            if (value)
            {
                CFRelease(value);
            }
            if (name && !value)
            {
                ret = 0;
            }

            CFRelease(dn);
            continue;
        }

        if (!appendCertField(pCertName, name, value))
        {
            ret = 0;
        }
        CFRelease(name);
        CFRelease(value);
        CFRelease(dn);
    }

    CFArrayAppendValue(names, pCertName);
    CFRelease(nameStrings);
    return ret;
}

int
arrayParseDescDataPair(const void *val, void *context)
{
    DescDataRef pDescData = (DescDataRef)val;
    CertDataRef pCertData = (CertDataRef)context;
    int ret = 1;

    if (!pDescData->name || !pDescData->value)
    {
        return 0;
    }

    if (CFStringCompareWithOptions(pDescData->name, kCertDataSubjectName, CFRangeMake(0, CFStringGetLength(pDescData->name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
    {
        ret = parseCertName(pDescData->value, (CFMutableArrayRef)pCertData->subject);
    }
    else if (CFStringCompareWithOptions(pDescData->name, kCertDataIssuerName, CFRangeMake(0, CFStringGetLength(pDescData->name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
    {
        ret = parseCertName(pDescData->value, (CFMutableArrayRef)pCertData->issuer);
    }
    else if (CFStringCompareWithOptions(pDescData->name, kCertDataSha1Name, CFRangeMake(0, CFStringGetLength(pDescData->name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
    {
        pCertData->sha1 = CFRetain(pDescData->value);
    }
    else if (CFStringCompareWithOptions(pDescData->name, kCertDataMd5Name, CFRangeMake(0, CFStringGetLength(pDescData->name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
    {
        pCertData->md5 = CFRetain(pDescData->value);
    }
    else if (CFStringCompareWithOptions(pDescData->name, kCertDataSerialName, CFRangeMake(0, CFStringGetLength(pDescData->name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
    {
        pCertData->serial = CFRetain(pDescData->value);
    }
    else
    {
        return 0;
    }

    return ret;
}

CertDataRef
createCertDataFromString(const char *description)
{
    CertDataRef pCertData = (CertDataRef)malloc(sizeof(CertData));
    pCertData->subject = CFArrayCreateMutable(NULL, 0, NULL);
    pCertData->issuer = CFArrayCreateMutable(NULL, 0, NULL);
    pCertData->sha1 = NULL;
    pCertData->md5 = NULL;
    pCertData->serial = NULL;

    CFArrayRef pairs = createDescDataPairs(description);
    for (int i = 0; i<CFArrayGetCount(pairs); i++)
        if (!arrayParseDescDataPair(CFArrayGetValueAtIndex(pairs, i), pCertData))
        {
            arrayDestroyDescData(pCertData, NULL);
            CFArrayApplyFunction(pairs, CFRangeMake(0, CFArrayGetCount(pairs)), arrayDestroyDescData, NULL);
            CFRelease(pairs);
            return 0;
        }

    CFArrayApplyFunction(pairs, CFRangeMake(0, CFArrayGetCount(pairs)), arrayDestroyDescData, NULL);
    CFRelease(pairs);
    return pCertData;
}

void
arrayDestroyCertName(const void *val, void *context)
{
    CertNameRef pCertName = (CertNameRef)val;
    destroyCertName(pCertName);
}

void
destroyCertData(CertDataRef pCertData)
{
    if (pCertData->subject)
    {
        CFArrayApplyFunction(pCertData->subject, CFRangeMake(0, CFArrayGetCount(pCertData->subject)), arrayDestroyCertName, NULL);
        CFRelease(pCertData->subject);
    }

    if (pCertData->issuer)
    {
        CFArrayApplyFunction(pCertData->issuer, CFRangeMake(0, CFArrayGetCount(pCertData->issuer)), arrayDestroyCertName, NULL);
        CFRelease(pCertData->issuer);
    }

    if (pCertData->sha1)
    {
        CFRelease(pCertData->sha1);
    }

    if (pCertData->md5)
    {
        CFRelease(pCertData->md5);
    }

    if (pCertData->serial)
    {
        CFRelease(pCertData->serial);
    }

    free(pCertData);
}

bool
stringArrayMatchesTemplate(CFArrayRef strings, CFArrayRef templateArray)
{
    int templateCount, stringCount, i;

    templateCount = CFArrayGetCount(templateArray);

    if (templateCount > 0)
    {
        stringCount = CFArrayGetCount(strings);
        if (stringCount != templateCount)
        {
            return false;
        }

        for (i = 0; i < stringCount; i++)
        {
            CFStringRef str, template;

            template = (CFStringRef)CFArrayGetValueAtIndex(templateArray, i);
            str = (CFStringRef)CFArrayGetValueAtIndex(strings, i);

            if (CFStringCompareWithOptions(template, str, CFRangeMake(0, CFStringGetLength(template)), kCFCompareCaseInsensitive) != kCFCompareEqualTo)
            {
                return false;
            }
        }
    }

    return true;

}

bool
certNameMatchesTemplate(CertNameRef pCertName, CertNameRef pTemplate)
{
    if (!stringArrayMatchesTemplate(pCertName->countryName, pTemplate->countryName))
    {
        return false;
    }
    else if (!stringArrayMatchesTemplate(pCertName->organization, pTemplate->organization))
    {
        return false;
    }
    else if (!stringArrayMatchesTemplate(pCertName->organizationalUnit, pTemplate->organizationalUnit))
    {
        return false;
    }
    else if (!stringArrayMatchesTemplate(pCertName->commonName, pTemplate->commonName))
    {
        return false;
    }
    else if (!stringArrayMatchesTemplate(pCertName->emailAddress, pTemplate->emailAddress))
    {
        return false;
    }
    else if (!stringArrayMatchesTemplate(pCertName->stateName, pTemplate->stateName))
    {
        return false;
    }
    else if (!stringArrayMatchesTemplate(pCertName->localityName, pTemplate->localityName))
    {
        return false;
    }
    else
    {
        return true;
    }
}

bool
certNameArrayMatchesTemplate(CFArrayRef certNameArray, CFArrayRef templateArray)
{
    int templateCount, certCount, i;

    templateCount = CFArrayGetCount(templateArray);

    if (templateCount > 0)
    {
        certCount = CFArrayGetCount(certNameArray);
        if (certCount != templateCount)
        {
            return false;
        }

        for (i = 0; i < certCount; i++)
        {
            CertNameRef pName, pTemplateName;

            pTemplateName = (CertNameRef)CFArrayGetValueAtIndex(templateArray, i);
            pName = (CertNameRef)CFArrayGetValueAtIndex(certNameArray, i);

            if (!certNameMatchesTemplate(pName, pTemplateName))
            {
                return false;
            }
        }
    }

    return true;
}

bool
hexStringMatchesTemplate(CFStringRef str, CFStringRef template)
{
    if (template)
    {
        if (!str)
        {
            return false;
        }

        CFMutableStringRef strMutable, templateMutable;

        strMutable = CFStringCreateMutableCopy(NULL, 0, str);
        templateMutable = CFStringCreateMutableCopy(NULL, 0, template);

        CFStringFindAndReplace(strMutable, kStringSpace, kStringEmpty, CFRangeMake(0, CFStringGetLength(strMutable)), 0);
        CFStringFindAndReplace(templateMutable, kStringSpace, kStringEmpty, CFRangeMake(0, CFStringGetLength(templateMutable)), 0);

        CFComparisonResult result = CFStringCompareWithOptions(templateMutable, strMutable, CFRangeMake(0, CFStringGetLength(templateMutable)), kCFCompareCaseInsensitive);

        CFRelease(strMutable);
        CFRelease(templateMutable);

        if (result != kCFCompareEqualTo)
        {
            return false;
        }
    }

    return true;
}

bool
certDataMatchesTemplate(CertDataRef pCertData, CertDataRef pTemplate)
{
    if (!certNameArrayMatchesTemplate(pCertData->subject, pTemplate->subject))
    {
        return false;
    }

    if (!certNameArrayMatchesTemplate(pCertData->issuer, pTemplate->issuer))
    {
        return false;
    }

    if (!hexStringMatchesTemplate(pCertData->sha1, pTemplate->sha1))
    {
        return false;
    }

    if (!hexStringMatchesTemplate(pCertData->md5, pTemplate->md5))
    {
        return false;
    }

    if (!hexStringMatchesTemplate(pCertData->serial, pTemplate->serial))
    {
        return false;
    }

    return true;
}

bool
certExpired(SecCertificateRef certificate)
{
    bool result;
    CFDateRef notAfter = GetDateFieldFromCertificate(certificate, kSecOIDX509V1ValidityNotAfter);
    CFDateRef notBefore = GetDateFieldFromCertificate(certificate, kSecOIDX509V1ValidityNotBefore);
    CFDateRef now = CFDateCreate(kCFAllocatorDefault, CFAbsoluteTimeGetCurrent());

    if (!notAfter || !notBefore || !now)
    {
        warnx("GetDateFieldFromCertificate() returned NULL");
        result = true;
    }
    else
    {
        if (CFDateCompare(notBefore, now, NULL) != kCFCompareLessThan
            || CFDateCompare(now, notAfter, NULL) != kCFCompareLessThan)
        {
            result = true;
        }
        else
        {
            result = false;
        }
    }

    CFRelease(notAfter);
    CFRelease(notBefore);
    CFRelease(now);
    return result;
}

SecIdentityRef
findIdentity(CertDataRef pCertDataTemplate)
{
    const void *keys[] = {
        kSecClass,
        kSecReturnRef,
        kSecMatchLimit
    };
    const void *values[] = {
        kSecClassIdentity,
        kCFBooleanTrue,
        kSecMatchLimitAll
    };
    CFArrayRef result = NULL;

    CFDictionaryRef query = CFDictionaryCreate(NULL, keys, values,
                                               sizeof(keys) / sizeof(*keys),
                                               &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&result);
    CFRelease(query);
    if (status != noErr)
    {
        warnx("No identities in keychain found");
        return NULL;
    }

    SecIdentityRef bestIdentity = NULL;
    CFDateRef bestNotBeforeDate = NULL;

    for (int i = 0; i<CFArrayGetCount(result); i++)
    {
        SecIdentityRef identity = (SecIdentityRef)CFArrayGetValueAtIndex(result, i);
        if (identity == NULL)
        {
            warnx("identity == NULL");
            continue;
        }

        SecCertificateRef certificate = NULL;
        SecIdentityCopyCertificate(identity, &certificate);
        if (certificate == NULL)
        {
            warnx("SecIdentityCopyCertificate() returned NULL");
            continue;
        }

        CertDataRef pCertData2 = createCertDataFromCertificate(certificate);
        if (pCertData2 == NULL)
        {
            warnx("createCertDataFromCertificate() returned NULL");
            goto release_cert;
        }
        bool bMatches = certDataMatchesTemplate(pCertData2, pCertDataTemplate);
        bool bExpired = certExpired(certificate);
        destroyCertData(pCertData2);

        if (bMatches && !bExpired)
        {
            CFDateRef notBeforeDate = GetDateFieldFromCertificate(certificate, kSecOIDX509V1ValidityNotBefore);
            if (!notBeforeDate)
            {
                warnx("GetDateFieldFromCertificate() returned NULL");
                goto release_cert;
            }
            if (bestIdentity == NULL)
            {
                CFRetain(identity);
                bestIdentity = identity;

                bestNotBeforeDate = notBeforeDate;
                CFRetain(notBeforeDate);
            }
            else if (CFDateCompare(bestNotBeforeDate, notBeforeDate, NULL) == kCFCompareLessThan)
            {
                CFRelease(bestIdentity);
                CFRetain(identity);
                bestIdentity = identity;

                bestNotBeforeDate = notBeforeDate;
                CFRetain(notBeforeDate);
            }
            CFRelease(notBeforeDate);
        }
release_cert:
        CFRelease(certificate);
    }
    CFRelease(result);

    return bestIdentity;
}
