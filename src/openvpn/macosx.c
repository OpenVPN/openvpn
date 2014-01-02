/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2010 Brian Raderman <brian@irregularexpression.org>
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
 *
 *  This is a concatenation of code originally in cert_data.c and crypto_osx.c,
 *  both by Brian Raderman <brian@irregularexpression.org> done by
 *  Radu - Eosif Mihailescu <rmihailescu@google.com>
 */

/*
 * Mac OS X-specific OpenVPN code.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#ifdef MACOSX

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdbool.h>
#include "buffer.h"
#include "macosx.h"

CFStringRef kCertDataSubjectName = CFSTR("subject"),
    kCertDataIssuerName = CFSTR("issuer"), kCertDataSha1Name = CFSTR("SHA1"),
    kCertDataMd5Name = CFSTR("MD5"), kCertNameFwdSlash = CFSTR("/"),
    kCertNameEquals = CFSTR("="),
    CFStringRef kCertNameOrganization = CFSTR("o"),
    kCertNameOrganizationalUnit = CFSTR("ou"), kCertNameCountry = CFSTR("c"),
    kCertNameLocality = CFSTR("l"), kCertNameState = CFSTR("st"),
    kCertNameCommonName = CFSTR("cn"), kCertNameEmail = CFSTR("e"),
    kCertNameDomainComponent = CFSTR("dc"), kStringSpace = CFSTR(" "),
    kStringEmpty = CFSTR("");

typedef struct
{
    CFArrayRef countryName, organization, organizationalUnit, commonName,
        description, emailAddress, stateName, localityName, distinguishedName,
        domainComponent;
} CertName, *CertNameRef;

typedef struct
{
    CFStringRef name, value;
} DescData, *DescDataRef;

typedef struct
{
    CFArrayRef subject;
    CFArrayRef issuer;
    CFStringRef md5, sha1;
} CertData, *CertDataRef;

static struct gc_arena g_gc;

static void initCertData()
{
    g_gc = gc_new();
}

static void freeCertData()
{
    gc_free(&g_gc);
}

static void appendHexChar(CFMutableStringRef str, unsigned char halfByte)
{
    if (halfByte < 10)
        CFStringAppendFormat (str, NULL, CFSTR("%d"), halfByte);
    else switch(halfByte)
    {
        case 10:
            CFStringAppendCString(str, "A", kCFStringEncodingUTF8);
            break;
        case 11:
            CFStringAppendCString(str, "B", kCFStringEncodingUTF8);
            break;
        case 12:
            CFStringAppendCString(str, "C", kCFStringEncodingUTF8);
            break;
        case 13:
            CFStringAppendCString(str, "D", kCFStringEncodingUTF8);
            break;
        case 14:
            CFStringAppendCString(str, "E", kCFStringEncodingUTF8);
            break;
        case 15:
            CFStringAppendCString(str, "F", kCFStringEncodingUTF8);
            break;
    }
}

static CFStringRef createHexString(unsigned char *pData, int length)
{
    unsigned char byte, low, high;
    int i;
    CFMutableStringRef str = CFStringCreateMutable(NULL, 0);

    for(i = 0;i < length;i++)
    {
        byte = pData[i];
        low = byte & 0x0F;
        high = (byte >> 4);

        appendHexChar(str, high);
        appendHexChar(str, low);

        if (i != (length - 1))
            CFStringAppendCString(str, " ", kCFStringEncodingUTF8);
    }

    return str;
}

static CertNameRef createCertName()
{
    CertNameRef pCertName = (CertNameRef)gc_malloc(sizeof(CertName), false, &g_gc);

    pCertName->countryName = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    pCertName->organization =  CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    pCertName->organizationalUnit = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    pCertName->commonName = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    pCertName->description = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    pCertName->emailAddress = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    pCertName->stateName = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    pCertName->localityName = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    pCertName->distinguishedName = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    pCertName->domainComponent = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);

    return pCertName;
}

static void destroyCertName(CertNameRef pCertName)
{
    if (!pCertName)
        return;

    CFRelease(pCertName->countryName);
    CFRelease(pCertName->organization);
    CFRelease(pCertName->organizationalUnit);
    CFRelease(pCertName->commonName);
    CFRelease(pCertName->description);
    CFRelease(pCertName->emailAddress);
    CFRelease(pCertName->stateName);
    CFRelease(pCertName->localityName);
    CFRelease(pCertName->distinguishedName);
    CFRelease(pCertName->domainComponent);
}


static CertNameRef dataToName(CSSM_DATA_PTR pData)
{
    CSSM_X509_NAME_PTR pName = (CSSM_X509_NAME_PTR)pData->Data;
    CertNameRef pCertName = createCertName();
    int i, j;

    for(i = 0;i < pName->numberOfRDNs;i++)
    {
        CSSM_X509_RDN rdn = pName->RelativeDistinguishedName[i];

        for(j = 0;j < rdn.numberOfPairs;j++)
        {
            CSSM_X509_TYPE_VALUE_PAIR nvp = rdn.AttributeTypeAndValue[j];
            CFStringRef str = CFStringCreateWithBytes (NULL, nvp.value.Data, nvp.value.Length, kCFStringEncodingUTF8, false);

            if (memcmp(nvp.type.Data, CSSMOID_CountryName.Data, CSSMOID_CountryName.Length) == 0)
                    CFArrayAppendValue((CFMutableArrayRef)pCertName->countryName, str);
            else if (memcmp(nvp.type.Data, CSSMOID_OrganizationName.Data, CSSMOID_OrganizationName.Length) == 0)
                    CFArrayAppendValue((CFMutableArrayRef)pCertName->organization, str);
            else if (memcmp(nvp.type.Data, CSSMOID_OrganizationalUnitName.Data, CSSMOID_OrganizationalUnitName.Length) == 0)
                    CFArrayAppendValue((CFMutableArrayRef)pCertName->organizationalUnit, str);
            else if (memcmp(nvp.type.Data, CSSMOID_CommonName.Data, CSSMOID_CommonName.Length) == 0)
                    CFArrayAppendValue((CFMutableArrayRef)pCertName->commonName, str);
            else if (memcmp(nvp.type.Data, CSSMOID_Description.Data, CSSMOID_Description.Length) == 0)
                    CFArrayAppendValue((CFMutableArrayRef)pCertName->description, str);
            else if (memcmp(nvp.type.Data, CSSMOID_EmailAddress.Data, CSSMOID_EmailAddress.Length) == 0)
                    CFArrayAppendValue((CFMutableArrayRef)pCertName->emailAddress, str);
            else if (memcmp(nvp.type.Data, CSSMOID_StateProvinceName.Data, CSSMOID_StateProvinceName.Length) == 0)
                    CFArrayAppendValue((CFMutableArrayRef)pCertName->stateName, str);
            else if (memcmp(nvp.type.Data, CSSMOID_LocalityName.Data, CSSMOID_LocalityName.Length) == 0)
                    CFArrayAppendValue((CFMutableArrayRef)pCertName->localityName, str);
            else if (memcmp(nvp.type.Data, CSSMOID_DistinguishedName.Data, CSSMOID_DistinguishedName.Length) == 0)
                    CFArrayAppendValue((CFMutableArrayRef)pCertName->distinguishedName, str);

            CFRelease(str);
        }
    }

    return pCertName;
}

static CFArrayRef GetFieldsFromCssmCertData(CSSM_CL_HANDLE hCL, CSSM_DATA_PTR pCertData, CSSM_OID oid)
{
    CSSM_DATA_PTR pData = NULL;
    CFMutableArrayRef fields = CFArrayCreateMutable(NULL, 0, NULL);
    uint32 numFields, i;
    CSSM_HANDLE ResultsHandle = (CSSM_HANDLE)NULL;
    numFields = 0;

    CSSM_CL_CertGetFirstFieldValue(hCL, pCertData, &oid, &ResultsHandle, &numFields, &pData);

    if (!pData)
    {
        CSSM_CL_CertAbortQuery(hCL, ResultsHandle);
        return NULL;
    }

    for (i = 0; i < numFields; i++)
    {
        CertNameRef pName = dataToName(pData);
        CFArrayAppendValue(fields, pName);
        CSSM_CL_FreeFieldValue (hCL, &oid, pData);
        if (i < (numFields - 1))
            CSSM_CL_CertGetNextFieldValue(hCL, ResultsHandle, &pData);
    }

    CSSM_CL_CertAbortQuery(hCL, ResultsHandle);
    return fields;
}

static CFArrayRef GetFieldsFromCertificate(SecCertificateRef certificate, CSSM_OID oid)
{
    CSSM_CL_HANDLE hCL;
    CSSM_DATA certData;
    CFArrayRef fieldValues;

    SecCertificateGetCLHandle(certificate, &hCL);
    SecCertificateGetData(certificate, &certData);
    fieldValues = GetFieldsFromCssmCertData(hCL, &certData, oid);

    if (fieldValues == NULL)
        return NULL;
    else if (CFArrayGetCount(fieldValues) == 0)
    {
        CFRelease(fieldValues);
        return NULL;
    }

    return fieldValues;
}

static CertDataRef createCertDataFromCertificate(SecCertificateRef certificate)
{
    CertDataRef pCertData = (CertDataRef)gc_malloc(sizeof(CertData), false, &g_gc);
    pCertData->subject = GetFieldsFromCertificate(certificate, CSSMOID_X509V1SubjectNameCStruct);
    pCertData->issuer = GetFieldsFromCertificate(certificate, CSSMOID_X509V1IssuerNameCStruct);

    CSSM_DATA cssmCertData;
    SecCertificateGetData (certificate, &cssmCertData);

    unsigned char sha1[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(cssmCertData.Data, cssmCertData.Length, sha1);
    pCertData->sha1 = createHexString(sha1, CC_SHA1_DIGEST_LENGTH);

    unsigned char md5[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cssmCertData.Data, cssmCertData.Length, md5);
    pCertData->md5 = createHexString((unsigned char*)md5, CC_MD5_DIGEST_LENGTH);

    return pCertData;
}

static CFStringRef stringFromRange(const char *cstring, CFRange range)
{
    CFStringRef str = CFStringCreateWithBytes (NULL, (uint8*)&cstring[range.location], range.length, kCFStringEncodingUTF8, false);
    CFMutableStringRef mutableStr = CFStringCreateMutableCopy(NULL, 0, str);
    CFStringTrimWhitespace(mutableStr);
    CFRelease(str);
    return mutableStr;
}

static DescDataRef createDescData(const char *description, CFRange nameRange, CFRange valueRange)
{
    DescDataRef pRetVal = (DescDataRef)gc_malloc(sizeof(DescData), false, &g_gc);

    memset(pRetVal, 0, sizeof(DescData));

    if (nameRange.length > 0)
            pRetVal->name = stringFromRange(description, nameRange);

    if (valueRange.length > 0)
            pRetVal->value = stringFromRange(description, valueRange);

    return pRetVal;
}

static void destroyDescData(DescDataRef pData)
{
    if (pData->name)
        CFRelease(pData->name);

    if (pData->value)
        CFRelease(pData->value);
}

static CFArrayRef createDescDataPairs(const char *description)
{
    int numChars = strlen(description);
    CFRange nameRange, valueRange;
    DescDataRef pData;
    CFMutableArrayRef retVal = CFArrayCreateMutable(NULL, 0, NULL);

    int i = 0;

    nameRange = CFRangeMake(0, 0);
    valueRange = CFRangeMake(0, 0);
    bool bInValue = false;

    while(i < numChars)
    {
        if (!bInValue && (description[i] != ':'))
            nameRange.length++;
        else if (bInValue && (description[i] != ':'))
            valueRange.length++;
        else if(!bInValue)
        {
            bInValue = true;
            valueRange.location = i + 1;
            valueRange.length = 0;
        }
        else //(bInValue)
        {
            bInValue = false;
            while(description[i] != ' ')
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

static void arrayDestroyDescData(const void *val, void *context)
{
    DescDataRef pData = (DescDataRef) val;
    destroyDescData(pData);
}


static void parseNameComponent(CFStringRef dn, CFStringRef *pName, CFStringRef *pValue)
{
    CFArrayRef nameStrings = CFStringCreateArrayBySeparatingStrings(NULL, dn, kCertNameEquals);

    *pName = *pValue = NULL;

    if (CFArrayGetCount(nameStrings) != 2)
        return;

    CFMutableStringRef str;

    str = CFStringCreateMutableCopy(NULL, 0, CFArrayGetValueAtIndex(nameStrings, 0));
    CFStringTrimWhitespace(str);
    *pName = str;

    str = CFStringCreateMutableCopy(NULL, 0, CFArrayGetValueAtIndex(nameStrings, 1));
    CFStringTrimWhitespace(str);
    *pValue = str;

    CFRelease(nameStrings);
}

static void parseCertName(CFStringRef nameDesc, CFMutableArrayRef names)
{
    CFArrayRef nameStrings = CFStringCreateArrayBySeparatingStrings(NULL, nameDesc, kCertNameFwdSlash);
    int count = CFArrayGetCount(nameStrings);
    int i;

    CertNameRef pCertName = createCertName();

    for(i = 0;i < count;i++)
    {
        CFMutableStringRef dn = CFStringCreateMutableCopy(NULL, 0, CFArrayGetValueAtIndex(nameStrings, i));
        CFStringTrimWhitespace(dn);

        CFStringRef name, value;

        parseNameComponent(dn, &name, &value);

        if (!name || !value)
        {
            if (name)
                CFRelease(name);

            if (value)
                CFRelease(value);

            CFRelease(dn);
            continue;
        }

        if (CFStringCompareWithOptions(name, kCertNameOrganization, CFRangeMake(0, CFStringGetLength(name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
            CFArrayAppendValue((CFMutableArrayRef)pCertName->organization, value);
        else if (CFStringCompareWithOptions(name, kCertNameOrganizationalUnit, CFRangeMake(0, CFStringGetLength(name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
            CFArrayAppendValue((CFMutableArrayRef)pCertName->organizationalUnit, value);
        else if (CFStringCompareWithOptions(name, kCertNameCountry, CFRangeMake(0, CFStringGetLength(name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
            CFArrayAppendValue((CFMutableArrayRef)pCertName->countryName, value);
        else if (CFStringCompareWithOptions(name, kCertNameLocality, CFRangeMake(0, CFStringGetLength(name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
            CFArrayAppendValue((CFMutableArrayRef)pCertName->localityName, value);
        else if (CFStringCompareWithOptions(name, kCertNameState, CFRangeMake(0, CFStringGetLength(name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
            CFArrayAppendValue((CFMutableArrayRef)pCertName->stateName, value);
        else if (CFStringCompareWithOptions(name, kCertNameCommonName, CFRangeMake(0, CFStringGetLength(name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
            CFArrayAppendValue((CFMutableArrayRef)pCertName->commonName, value);
        else if (CFStringCompareWithOptions(name, kCertNameEmail, CFRangeMake(0, CFStringGetLength(name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
            CFArrayAppendValue((CFMutableArrayRef)pCertName->emailAddress, value);
        else if (CFStringCompareWithOptions(name, kCertNameDomainComponent, CFRangeMake(0, CFStringGetLength(name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
            CFArrayAppendValue((CFMutableArrayRef)pCertName->domainComponent, value);

        CFRelease(name);
        CFRelease(value);
        CFRelease(dn);
    }

    CFArrayAppendValue(names, pCertName);
    CFRelease(nameStrings);
}

static void arrayParseDescDataPair(const void *val, void *context)
{
    DescDataRef pDescData = (DescDataRef)val;
    CertDataRef pCertData = (CertDataRef)context;

    if (!pDescData->name || !pDescData->value)
        return;

    if (CFStringCompareWithOptions(pDescData->name, kCertDataSubjectName, CFRangeMake(0, CFStringGetLength(pDescData->name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
        parseCertName(pDescData->value, (CFMutableArrayRef)pCertData->subject);
    else if (CFStringCompareWithOptions(pDescData->name, kCertDataIssuerName, CFRangeMake(0, CFStringGetLength(pDescData->name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
        parseCertName(pDescData->value, (CFMutableArrayRef)pCertData->issuer);
    else if (CFStringCompareWithOptions(pDescData->name, kCertDataSha1Name, CFRangeMake(0, CFStringGetLength(pDescData->name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
        pCertData->sha1 = CFRetain(pDescData->value);
    else if (CFStringCompareWithOptions(pDescData->name, kCertDataMd5Name, CFRangeMake(0, CFStringGetLength(pDescData->name)), kCFCompareCaseInsensitive) == kCFCompareEqualTo)
        pCertData->md5 = CFRetain(pDescData->value);
}

static CertDataRef createCertDataFromString(const char *description)
{
    CertDataRef pCertData = (CertDataRef)gc_malloc(sizeof(CertData), false, &g_gc);
    pCertData->subject = CFArrayCreateMutable(NULL, 0, NULL);
    pCertData->issuer = CFArrayCreateMutable(NULL, 0, NULL);
    pCertData->sha1 = NULL;
    pCertData->md5 = NULL;

    CFArrayRef pairs = createDescDataPairs(description);
    CFArrayApplyFunction(pairs, CFRangeMake(0, CFArrayGetCount(pairs)), arrayParseDescDataPair, pCertData);
    CFArrayApplyFunction(pairs, CFRangeMake(0, CFArrayGetCount(pairs)), arrayDestroyDescData, NULL);
    CFRelease(pairs);
    return pCertData;
}

static void arrayDestroyCertName(const void *val, void *context)
{
    CertNameRef pCertName = (CertNameRef)val;
    destroyCertName(pCertName);
}

static void destroyCertData(CertDataRef pCertData)
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
        CFRelease(pCertData->sha1);

    if (pCertData->md5)
        CFRelease(pCertData->md5);
}

static bool stringArrayMatchesTemplate(CFArrayRef strings, CFArrayRef templateArray)
{
    int templateCount, stringCount, i;

    templateCount = CFArrayGetCount(templateArray);

    if (templateCount > 0)
    {
        stringCount = CFArrayGetCount(strings);
        if (stringCount != templateCount)
            return false;

        for(i = 0;i < stringCount;i++)
        {
            CFStringRef str, template;

            template = (CFStringRef)CFArrayGetValueAtIndex(templateArray, i);
            str = (CFStringRef)CFArrayGetValueAtIndex(strings, i);

            if (CFStringCompareWithOptions(template, str, CFRangeMake(0, CFStringGetLength(template)), kCFCompareCaseInsensitive) != kCFCompareEqualTo)
                return false;
        }
    }

    return true;
}

static bool certNameMatchesTemplate(CertNameRef pCertName, CertNameRef pTemplate)
{
    if (!stringArrayMatchesTemplate(pCertName->countryName, pTemplate->countryName))
        return false;
    else if (!stringArrayMatchesTemplate(pCertName->organization, pTemplate->organization))
        return false;
    else if (!stringArrayMatchesTemplate(pCertName->organizationalUnit, pTemplate->organizationalUnit))
        return false;
    else if (!stringArrayMatchesTemplate(pCertName->commonName, pTemplate->commonName))
        return false;
    else if (!stringArrayMatchesTemplate(pCertName->emailAddress, pTemplate->emailAddress))
        return false;
    else if (!stringArrayMatchesTemplate(pCertName->stateName, pTemplate->stateName))
        return false;
    else if (!stringArrayMatchesTemplate(pCertName->localityName, pTemplate->localityName))
        return false;
    else
        return true;
}

static bool certNameArrayMatchesTemplate(CFArrayRef certNameArray, CFArrayRef templateArray)
{
    int templateCount, certCount, i;

    templateCount = CFArrayGetCount(templateArray);

    if (templateCount > 0)
    {
        certCount = CFArrayGetCount(certNameArray);
        if (certCount != templateCount)
            return false;

        for(i = 0;i < certCount;i++)
        {
            CertNameRef pName, pTemplateName;

            pTemplateName = (CertNameRef)CFArrayGetValueAtIndex(templateArray, i);
            pName = (CertNameRef)CFArrayGetValueAtIndex(certNameArray, i);

            if (!certNameMatchesTemplate(pName, pTemplateName))
                return false;
        }
    }

    return true;
}

static bool hexStringMatchesTemplate(CFStringRef str, CFStringRef template)
{
    if (template)
    {
        if (!str)
            return false;

        CFMutableStringRef strMutable, templateMutable;

        strMutable = CFStringCreateMutableCopy(NULL, 0, str);
        templateMutable = CFStringCreateMutableCopy(NULL, 0, template);

        CFStringFindAndReplace(strMutable, kStringSpace, kStringEmpty, CFRangeMake(0, CFStringGetLength(strMutable)), 0);
        CFStringFindAndReplace(templateMutable, kStringSpace, kStringEmpty, CFRangeMake(0, CFStringGetLength(templateMutable)), 0);

        CFComparisonResult result = CFStringCompareWithOptions(templateMutable, strMutable, CFRangeMake(0, CFStringGetLength(templateMutable)), kCFCompareCaseInsensitive);

        CFRelease(strMutable);
        CFRelease(templateMutable);

        if (result != kCFCompareEqualTo)
            return false;
    }

    return true;
}

static bool certDataMatchesTemplate(CertDataRef pCertData, CertDataRef pTemplate)
{
    if (!certNameArrayMatchesTemplate(pCertData->subject, pTemplate->subject))
        return false;

    if (!certNameArrayMatchesTemplate(pCertData->issuer, pTemplate->issuer))
        return false;

    if (!hexStringMatchesTemplate(pCertData->sha1, pTemplate->sha1))
        return false;

    if (!hexStringMatchesTemplate(pCertData->md5, pTemplate->md5))
        return false;

    return true;
}

static SecIdentityRef findIdentity(CertDataRef pCertDataTemplate)
{
    SecIdentitySearchRef search;
    SecIdentitySearchCreate(NULL, 0, &search);

    SecIdentityRef identity;
    while(SecIdentitySearchCopyNext(search, &identity) != errSecItemNotFound)
    {
        SecCertificateRef certificate;
        SecIdentityCopyCertificate (identity, &certificate);

        CertDataRef pCertData = createCertDataFromCertificate(certificate);
        bool bMatches = certDataMatchesTemplate(pCertData, pCertDataTemplate);

        destroyCertData(pCertData);
        CFRelease(certificate);

        if (bMatches)
            break;
        else
        {
            CFRelease(identity);
            identity = NULL;
        }
    }

    CFRelease(search);
    return identity;
}

static CSSM_DATA signData(SecIdentityRef identity, CSSM_DATA dataBuf)
{
    SecKeyRef privateKey;

    SecIdentityCopyPrivateKey(identity,  &privateKey);
    const CSSM_ACCESS_CREDENTIALS *pCredentials;
    SecKeyGetCredentials(privateKey, CSSM_ACL_AUTHORIZATION_SIGN, kSecCredentialTypeDefault, &pCredentials);

    CSSM_CSP_HANDLE cspHandle;
    SecKeyGetCSPHandle(privateKey, &cspHandle);

    const CSSM_KEY *pCssmKey;
    SecKeyGetCSSMKey (privateKey, &pCssmKey);

    CSSM_DATA signBuf;
    signBuf.Data = NULL;
    signBuf.Length = 0;

    if (!(pCssmKey->KeyHeader.KeyUsage & CSSM_KEYUSE_SIGN))
    {
        CFRelease(privateKey);
        return signBuf;
    }

    CSSM_CC_HANDLE cryptoContextHandle;
    CSSM_CSP_CreateSignatureContext(cspHandle, CSSM_ALGID_RSA, pCredentials, pCssmKey, &cryptoContextHandle);

    CSSM_SignData(cryptoContextHandle, &dataBuf, 1, CSSM_ALGID_NONE, &signBuf);

    CSSM_DeleteContext(cryptoContextHandle);
    CFRelease(privateKey);
    return signBuf;
}

static void freeSignature(SecIdentityRef identity, CSSM_DATA sigBuf)
{
    SecKeyRef privateKey;

    SecIdentityCopyPrivateKey(identity,  &privateKey);

    CSSM_CSP_HANDLE cspHandle;
    SecKeyGetCSPHandle(privateKey, &cspHandle);

    CSSM_API_MEMORY_FUNCS memFuncs;
    CSSM_GetAPIMemoryFunctions(cspHandle, &memFuncs);

    memFuncs.free_func(sigBuf.Data, memFuncs.AllocRef);
}

/* --- Everything above is private, everything below is public API --- */

void extractCertificateFromIdentity(SecIdentityRef identity, void **blob, size_t *size)
{
    CSSM_DATA cssmCertData;
    SecCertificateRef certificate;

    SecIdentityCopyCertificate(identity, &certificate);
    SecCertificateGetData(certificate, &cssmCertData);
    CFRelease(certificate);

    *blob = cssmCertData.Data;
    *length = cssmCertData.Length;
}

SecIdentityRef findIdentityByString(const char *description)
{
    initCertData();

    CertDataRef pCertDataTemplate = createCertDataFromString(description);
    SecIdentityRef identity = findIdentity(pCertDataTemplate);
    destroyCertData(pCertDataTemplate);

    freeCertData();

    return identity;
}

void cryptoSignData(SecIdentityRef identity, const unsigned char *data, size_t size, unsigned char *signature)
{
    CSSM_DATA fromData;
    fromData.Data = (uint8*)data;
    fromData.Length = size;

    CSSM_DATA sigBuf = signData(identity, fromData);
    memcpy(signature, sigBuf.Data, sigBuf.Length);
    freeSignature(identity, sigBuf);
}

#endif
