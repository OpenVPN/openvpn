/*
 This Software is provided under the Zope Public License (ZPL) Version 2.1.

 Copyright (c) 2009, 2010 by the mingw-w64 project

 See the AUTHORS file for the list of contributors to the mingw-w64 project.

 This license has been certified as open source. It has also been designated
 as GPL compatible by the Free Software Foundation (FSF).

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

   1. Redistributions in source code must retain the accompanying copyright
      notice, this list of conditions, and the following disclaimer.
   2. Redistributions in binary form must reproduce the accompanying
      copyright notice, this list of conditions, and the following disclaimer
      in the documentation and/or other materials provided with the
      distribution.
   3. Names of the copyright holders must not be used to endorse or promote
      products derived from this software without prior written permission
      from the copyright holders.
   4. The right to distribute this software or to use it for any purpose does
      not give you the right to use Servicemarks (sm) or Trademarks (tm) of
      the copyright holders.  Use of them is covered by separate agreement
      with the copyright holders.
   5. If any files are modified, you must cause the modified files to carry
      prominent notices stating that you changed the files and the date of
      any change.

 Disclaimer

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ``AS IS'' AND ANY EXPRESSED
 OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Windows Filtering Platform (WFP) related prototypes, mostly stripped out of
 * mingw-w64.
 */

/*
 * WFP-related defines and GUIDs.
 */

#ifndef WIN32_WFP_H
#define WIN32_WFP_H

#include <initguid.h>
#include <iphlpapi.h>
#include <rpc.h>
#include <rpcdce.h>

#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#endif

// c38d57d1-05a7-4c33-904f-7fbceee60e82
DEFINE_GUID(
   FWPM_LAYER_ALE_AUTH_CONNECT_V4,
   0xc38d57d1,
   0x05a7,
   0x4c33,
   0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82
);

// 4a72393b-319f-44bc-84c3-ba54dcb3b6b4
DEFINE_GUID(
   FWPM_LAYER_ALE_AUTH_CONNECT_V6,
   0x4a72393b,
   0x319f,
   0x44bc,
   0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4
);

// d78e1e87-8644-4ea5-9437-d809ecefc971
DEFINE_GUID(
   FWPM_CONDITION_ALE_APP_ID,
   0xd78e1e87,
   0x8644,
   0x4ea5,
   0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71
);

// c35a604d-d22b-4e1a-91b4-68f674ee674b
DEFINE_GUID(
   FWPM_CONDITION_IP_REMOTE_PORT,
   0xc35a604d,
   0xd22b,
   0x4e1a,
   0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b
);

// 4cd62a49-59c3-4969-b7f3-bda5d32890a4
DEFINE_GUID(
   FWPM_CONDITION_IP_LOCAL_INTERFACE,
   0x4cd62a49,
   0x59c3,
   0x4969,
   0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4
);

/* From fwptypes.h */

#define FWP_ACTION_FLAG_TERMINATING     (0x00001000)
#define FWP_ACTION_FLAG_NON_TERMINATING (0x00002000)

#define FWP_ACTION_BLOCK  (0x1 | FWP_ACTION_FLAG_TERMINATING)
#define FWP_ACTION_PERMIT (0x2 | FWP_ACTION_FLAG_TERMINATING)

typedef UINT32 FWP_ACTION_TYPE;

typedef enum FWP_DATA_TYPE_ {
    FWP_EMPTY = 0,
    FWP_UINT8 = 1,
    FWP_UINT16 = 2,
    FWP_UINT32 = 3,
    FWP_UINT64 = 4,
    FWP_INT8 = 5,
    FWP_INT16 = 6,
    FWP_INT32 = 7,
    FWP_INT64 = 8,
    FWP_FLOAT = 9,
    FWP_DOUBLE = 10,
    FWP_BYTE_ARRAY16_TYPE = 11,
    FWP_BYTE_BLOB_TYPE = 12,
    FWP_SID = 13,
    FWP_SECURITY_DESCRIPTOR_TYPE = 14,
    FWP_TOKEN_INFORMATION_TYPE = 15,
    FWP_TOKEN_ACCESS_INFORMATION_TYPE = 16,
    FWP_UNICODE_STRING_TYPE = 17,
    FWP_BYTE_ARRAY6_TYPE = 18,
    FWP_SINGLE_DATA_TYPE_MAX = 0xff,
    FWP_V4_ADDR_MASK = 0x100,
    FWP_V6_ADDR_MASK = 0x101,
    FWP_RANGE_TYPE = 0x102,
    FWP_DATA_TYPE_MAX = 0x103
} FWP_DATA_TYPE;

typedef enum FWP_MATCH_TYPE_ {
    FWP_MATCH_EQUAL = 0,
    FWP_MATCH_GREATER = 1,
    FWP_MATCH_LESS = 2,
    FWP_MATCH_GREATER_OR_EQUAL = 3,
    FWP_MATCH_LESS_OR_EQUAL = 4,
    FWP_MATCH_RANGE = 5,
    FWP_MATCH_FLAGS_ALL_SET = 6,
    FWP_MATCH_FLAGS_ANY_SET = 7,
    FWP_MATCH_FLAGS_NONE_SET = 8,
    FWP_MATCH_EQUAL_CASE_INSENSITIVE = 9,
    FWP_MATCH_NOT_EQUAL = 10,
    FWP_MATCH_TYPE_MAX = 11
} FWP_MATCH_TYPE;

typedef struct FWP_BYTE_ARRAY6_ {
    UINT8 byteArray6[6];
} FWP_BYTE_ARRAY6;

typedef struct FWP_BYTE_ARRAY16_ {
    UINT8 byteArray16[16];
} FWP_BYTE_ARRAY16;

typedef struct FWP_BYTE_BLOB_ {
    UINT32 size;
    UINT8 *data;
} FWP_BYTE_BLOB;

typedef struct FWP_TOKEN_INFORMATION_ {
    ULONG sidCount;
    PSID_AND_ATTRIBUTES sids;
    ULONG restrictedSidCount;
    PSID_AND_ATTRIBUTES restrictedSids;
} FWP_TOKEN_INFORMATION;

typedef struct FWP_VALUE0_ {
    FWP_DATA_TYPE type;
    union {
        UINT8 uint8;
        UINT16 uint16;
        UINT32 uint32;
        UINT64 *uint64;
        INT8 int8;
        INT16 int16;
        INT32 int32;
        INT64 *int64;
        float float32;
        double *double64;
        FWP_BYTE_ARRAY16 *byteArray16;
        FWP_BYTE_BLOB *byteBlob;
        SID *sid;
        FWP_BYTE_BLOB *sd;
        FWP_TOKEN_INFORMATION *tokenInformation;
        FWP_BYTE_BLOB *tokenAccessInformation;
        LPWSTR unicodeString;
        FWP_BYTE_ARRAY6 *byteArray6;
    };
} FWP_VALUE0;

typedef struct FWP_V4_ADDR_AND_MASK_ {
    UINT32 addr;
    UINT32 mask;
} FWP_V4_ADDR_AND_MASK;

typedef struct FWP_V6_ADDR_AND_MASK_ {
    UINT8 addr[16];
    UINT8 prefixLength;
} FWP_V6_ADDR_AND_MASK;

typedef struct FWP_RANGE0_ {
    FWP_VALUE0 valueLow;
    FWP_VALUE0 valueHigh;
} FWP_RANGE0;

typedef struct FWP_CONDITION_VALUE0_ {
    FWP_DATA_TYPE type;
    union {
        UINT8 uint8;
        UINT16 uint16;
        UINT32 uint32;
        UINT64 *uint64;
        INT8 int8;
        INT16 int16;
        INT32 int32;
        INT64 *int64;
        float float32;
        double *double64;
        FWP_BYTE_ARRAY16 *byteArray16;
        FWP_BYTE_BLOB *byteBlob;
        SID *sid;
        FWP_BYTE_BLOB *sd;
        FWP_TOKEN_INFORMATION *tokenInformation;
        FWP_BYTE_BLOB *tokenAccessInformation;
        LPWSTR unicodeString;
        FWP_BYTE_ARRAY6 *byteArray6;
        FWP_V4_ADDR_AND_MASK *v4AddrMask;
        FWP_V6_ADDR_AND_MASK *v6AddrMask;
        FWP_RANGE0 *rangeValue;
    };
} FWP_CONDITION_VALUE0;

typedef struct FWPM_DISPLAY_DATA0_ {
    wchar_t *name;
    wchar_t *description;
} FWPM_DISPLAY_DATA0;

/* From fwpmtypes.h */

typedef struct FWPM_ACTION0_ {
  FWP_ACTION_TYPE type;
  union {
    GUID filterType;
    GUID calloutKey;
  };
} FWPM_ACTION0;

typedef struct FWPM_SESSION0_ {
  GUID               sessionKey;
  FWPM_DISPLAY_DATA0 displayData;
  UINT32             flags;
  UINT32             txnWaitTimeoutInMSec;
  DWORD              processId;
  SID                *sid;
  wchar_t            *username;
  BOOL            kernelMode;
} FWPM_SESSION0;

typedef struct FWPM_SUBLAYER0_ {
  GUID               subLayerKey;
  FWPM_DISPLAY_DATA0 displayData;
  UINT16             flags;
  GUID               *providerKey;
  FWP_BYTE_BLOB      providerData;
  UINT16             weight;
} FWPM_SUBLAYER0;

typedef struct FWPM_FILTER_CONDITION0_ {
  GUID                 fieldKey;
  FWP_MATCH_TYPE       matchType;
  FWP_CONDITION_VALUE0 conditionValue;
} FWPM_FILTER_CONDITION0;

typedef struct FWPM_FILTER0_ {
  GUID                   filterKey;
  FWPM_DISPLAY_DATA0     displayData;
  UINT32                 flags;
  GUID                   *providerKey;
  FWP_BYTE_BLOB          providerData;
  GUID                   layerKey;
  GUID                   subLayerKey;
  FWP_VALUE0             weight;
  UINT32                 numFilterConditions;
  FWPM_FILTER_CONDITION0 *filterCondition;
  FWPM_ACTION0           action;
  union {
    UINT64 rawContext;
    GUID   providerContextKey;
  };
  GUID                   *reserved;
  UINT64                 filterId;
  FWP_VALUE0             effectiveWeight;
} FWPM_FILTER0;

/* Typedefs of WFP functions */

#define NETIO_STATUS DWORD

typedef NETIO_STATUS *(WINAPI *func_ConvertInterfaceIndexToLuid)(
  NET_IFINDEX InterfaceIndex,
  PNET_LUID InterfaceLuid
);

typedef DWORD *(WINAPI *func_FwpmEngineOpen0)(
  const wchar_t *serverName,
  UINT32 authnService,
  SEC_WINNT_AUTH_IDENTITY_W *authIdentity,
  const FWPM_SESSION0 *session,
  HANDLE *engineHandle
);

typedef DWORD *(WINAPI *func_FwpmEngineClose0)(
  HANDLE engineHandle
);

typedef DWORD *(WINAPI *func_FwpmFilterAdd0)(
  HANDLE engineHandle,
  const FWPM_FILTER0 *filter,
  PSECURITY_DESCRIPTOR sd,
  UINT64 *id
);

typedef DWORD *(WINAPI *func_FwpmSubLayerAdd0)(
  HANDLE engineHandle,
  const FWPM_SUBLAYER0 *subLayer,
  PSECURITY_DESCRIPTOR sd
);

typedef DWORD *(WINAPI *func_FwpmSubLayerDeleteByKey0)(
  HANDLE engineHandle,
  const GUID *key
);

typedef void *(WINAPI *func_FwpmFreeMemory0)(
  void **p
);

typedef DWORD *(WINAPI *func_FwpmGetAppIdFromFileName0)(
  const wchar_t *fileName,
  FWP_BYTE_BLOB **appId
);

#endif
